// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package policy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"
	ackmetrics "github.com/aws-controllers-k8s/runtime/pkg/metrics"
	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/aws-controllers-k8s/iam-controller/apis/v1alpha1"
)

const testPolicyARN = "arn:aws:iam::123456789012:policy/test-policy"

// fakeIAMPolicyAPI is a fake IAM HTTP client that serves GetPolicy and
// GetPolicyVersion for the policies it holds, keyed by ARN, and records the
// query of every request.
type fakeIAMPolicyAPI struct {
	policies map[string]string // ARN -> policy document (JSON)
	requests []url.Values
}

func (c *fakeIAMPolicyAPI) Do(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	c.requests = append(c.requests, form)

	action := form.Get("Action")
	arn := form.Get("PolicyArn")
	document, ok := c.policies[arn]
	if !ok {
		return xmlResponse(req, http.StatusNotFound, fmt.Sprintf(
			`<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>Policy %s does not exist or is not attachable.</Message></Error><RequestId>test</RequestId></ErrorResponse>`,
			arn,
		)), nil
	}
	switch action {
	case "GetPolicy":
		name := arn[strings.LastIndex(arn, "/")+1:]
		return xmlResponse(req, http.StatusOK, fmt.Sprintf(
			`<GetPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetPolicyResult><Policy><PolicyName>%s</PolicyName><DefaultVersionId>v1</DefaultVersionId><PolicyId>ANPATEST</PolicyId><Path>/</Path><Arn>%s</Arn><AttachmentCount>0</AttachmentCount><IsAttachable>true</IsAttachable></Policy></GetPolicyResult><ResponseMetadata><RequestId>test</RequestId></ResponseMetadata></GetPolicyResponse>`,
			name, arn,
		)), nil
	case "GetPolicyVersion":
		return xmlResponse(req, http.StatusOK, fmt.Sprintf(
			`<GetPolicyVersionResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetPolicyVersionResult><PolicyVersion><Document>%s</Document><VersionId>v1</VersionId><IsDefaultVersion>true</IsDefaultVersion></PolicyVersion></GetPolicyVersionResult><ResponseMetadata><RequestId>test</RequestId></ResponseMetadata></GetPolicyVersionResponse>`,
			url.QueryEscape(document),
		)), nil
	}
	return nil, fmt.Errorf("unexpected IAM action %q", action)
}

func xmlResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"text/xml"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func newFakeIAMResourceManager(fake *fakeIAMPolicyAPI) *resourceManager {
	return &resourceManager{
		awsPartition: "aws",
		awsAccountID: "123456789012",
		metrics:      ackmetrics.NewMetrics("iam"),
		sdkapi: svcsdk.New(svcsdk.Options{
			Region:      "us-east-1",
			Credentials: aws.AnonymousCredentials{},
			HTTPClient:  fake,
			Retryer:     aws.NopRetryer{},
		}),
	}
}

// policyWithoutARN returns a Policy whose status has no ARN.
func policyWithoutARN() *resource {
	return &resource{ko: &svcapitypes.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: svcapitypes.PolicySpec{
			Name:           aws.String("test-policy"),
			PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[]}`),
		},
	}}
}

// ReadOne looks up a Policy whose status has no ARN by the ARN derived from
// its name. ReadOne does not look at the finalizer, so a resource the
// controller created but whose ARN never reached the status (the controller
// stopped right after CreatePolicy, or the status patch failed) and a new
// resource take the same path here.
//
// What the runtime does next depends on the finalizer, and the e2e tests
// cover it: a managed resource gets its ARN back instead of failing with
// EntityAlreadyExists (test_lost_arn_is_found_by_name), and a new resource
// whose name is taken stops with the NotManaged terminal condition
// (test_existing_policy_by_name). NotFound makes the runtime call CreatePolicy.
func TestReadOne_PolicyWithoutARN(t *testing.T) {
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

	tests := []struct {
		name     string
		policies map[string]string
		wantErr  error
	}{
		{
			name:     "policy exists",
			policies: map[string]string{testPolicyARN: document},
		},
		{
			name:     "policy does not exist",
			policies: map[string]string{},
			wantErr:  ackerr.NotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeIAMPolicyAPI{policies: tt.policies}
			rm := newFakeIAMResourceManager(fake)

			latest, err := rm.ReadOne(context.Background(), policyWithoutARN())

			require.NotEmpty(t, fake.requests)
			assert.Equal(t, "GetPolicy", fake.requests[0].Get("Action"))
			assert.Equal(t, testPolicyARN, fake.requests[0].Get("PolicyArn"))

			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				assert.Len(t, fake.requests, 1)
				return
			}
			require.NoError(t, err)
			ko := rm.concreteResource(latest).ko
			require.NotNil(t, ko.Status.ACKResourceMetadata)
			require.NotNil(t, ko.Status.ACKResourceMetadata.ARN)
			assert.Equal(t, testPolicyARN, string(*ko.Status.ACKResourceMetadata.ARN))
			require.NotNil(t, ko.Spec.PolicyDocument)
			assert.Equal(t, document, *ko.Spec.PolicyDocument)
		})
	}
}
