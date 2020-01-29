/*
Copyright (c) 2020 Synopsys, Inc.

Added API calls to artifactory to test policy violations

Copyright (c) 2019 StackRox Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	tlsDir      = `/run/secrets/tls`
	tlsCertFile = `tls.crt`
	tlsKeyFile  = `tls.key`
)

var (
	podResource = metav1.GroupVersionResource{Version: "v1", Resource: "pods"}
)

// applySecurityDefaults implements the logic of our example admission controller webhook. For every pod that is created
// (outside of Kubernetes namespaces), it first checks if `runAsNonRoot` is set. If it is not, it is set to a default
// value of `false`. Furthermore, if `runAsUser` is not set (and `runAsNonRoot` was not initially set), it defaults
// `runAsUser` to a value of 1234.
//
// To demonstrate how requests can be rejected, this webhook further validates that the `runAsNonRoot` setting does
// not conflict with the `runAsUser` setting - i.e., if the former is set to `true`, the latter must not be `0`.
// Note that we combine both the setting of defaults and the check for potential conflicts in one webhook; ideally,
// the latter would be performed in a validating webhook admission controller.
func applySecurityDefaults(req *v1beta1.AdmissionRequest) ([]patchOperation, error) {
	// This handler should only get called on Pod objects as per the MutatingWebhookConfiguration in the YAML file.
	// However, if (for whatever reason) this gets invoked on an object of a different kind, issue a log message but
	// let the object request pass through otherwise.
	if req.Resource != podResource {
		log.Println("expect resource to be %s", podResource)
		return nil, nil
	}

	// Parse the Pod object.
	raw := req.Object.Raw
	pod := corev1.Pod{}
	if _, _, err := universalDeserializer.Decode(raw, nil, &pod); err != nil {
		return nil, fmt.Errorf("could not deserialize pod object: %v", err)
	}

	// Retrieve the `runAsNonRoot` and `runAsUser` values.
	// var runAsNonRoot *bool
	// var runAsUser *int64
	// if pod.Spec.SecurityContext != nil {
	// 	runAsNonRoot = pod.Spec.SecurityContext.RunAsNonRoot
	// 	runAsUser = pod.Spec.SecurityContext.RunAsUser
	// }
	cred := &RegistryAuth{
		URL:      "salesaf.blackducksoftware.com",
		User:     "gautamb",
		Password: "",
	}

	fmt.Println("AC webhook: ", pod.Spec.Containers[0].Image)
	image := pod.Spec.Containers[0].Image
	imageSplit := strings.Split(image, ":")

	imageName := imageSplit[0]
	imageVersion := "latest"
	if len(imageSplit) > 1 {
		imageVersion = imageSplit[1]
	}

	artStatus := &ArtStatus{}
	url := fmt.Sprintf("https://%s/artifactory/api/storage/%s/%s/%s?properties=blackduck.overallStatus", cred.URL, "docker-local", imageName, imageVersion)
	fmt.Println("AC webhook: url~> ", url)

	err := GetResourceOfType(url, cred, artStatus)
	if err != nil {
		fmt.Println("AC webhook: Error: ", imageName, ":", imageVersion, " ", err)
	} else {
		fmt.Println("AC webhook: image", imageName, ":", imageVersion, " is an artifactory image")
		for _, violation := range artStatus.Properties.BlackduckOverallStatus {
			fmt.Println("AC webhook: violation status ~> ", violation)
			if violation == "IN_VIOLATION" {
				return nil, fmt.Errorf("AC webhook: Black Duck policy violation for the image %s:%s", imageName, imageVersion)
			}
		}

		fmt.Println("AC webhook: Artifactory image ", imageName, ":", imageVersion, "not in Black Duck status violation")
	}

	// Create patch operations to apply sensible defaults, if those options are not set explicitly.
	var patches []patchOperation
	// if runAsNonRoot == nil {
	// 	patches = append(patches, patchOperation{
	// 		Op:   "add",
	// 		Path: "/spec/securityContext/runAsNonRoot",
	// 		// The value must not be true if runAsUser is set to 0, as otherwise we would create a conflicting
	// 		// configuration ourselves.
	// 		Value: runAsUser == nil || *runAsUser != 0,
	// 	})

	// 	if runAsUser == nil {
	// 		patches = append(patches, patchOperation{
	// 			Op:    "add",
	// 			Path:  "/spec/securityContext/runAsUser",
	// 			Value: 1234,
	// 		})
	// 	}
	// } else if *runAsNonRoot == true && (runAsUser != nil && *runAsUser == 0) {
	// 	// Make sure that the settings are not contradictory, and fail the object creation if they are.
	// 	return nil, errors.New("runAsNonRoot specified, but runAsUser set to 0 (the root user)")
	// }

	return patches, nil
}

func main() {
	certPath := filepath.Join(tlsDir, tlsCertFile)
	keyPath := filepath.Join(tlsDir, tlsKeyFile)

	mux := http.NewServeMux()
	mux.Handle("/mutate", admitFuncHandler(applySecurityDefaults))
	server := &http.Server{
		// We listen on port 8443 such that we do not need root privileges or extra capabilities for this server.
		// The Service object will take care of mapping this port to the HTTPS port 443.
		Addr:    ":8443",
		Handler: mux,
	}
	log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}

// GetResourceOfType takes in the specified URL with credentials and
// tries to decode returning json to specified interface
func GetResourceOfType(url string, cred *RegistryAuth, target interface{}) error {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("Error in creating get request %e at url %s", err, url)
	}

	if cred != nil {
		req.SetBasicAuth(cred.User, cred.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

// RegistryAuth stores the credentials for a private docker repo
// and is same as common.RegistryAuth in perceptor-scanner repo
type RegistryAuth struct {
	URL      string
	User     string
	Password string
	Token    string
}

// ArtImageSHAs gets all the sha256 of an image
type ArtImageSHAs struct {
	Properties struct {
		Sha256 []string `json:"sha256"`
	} `json:"properties"`
	URI string `json:"uri"`
}

// ArtStatus gets status violation policy
type ArtStatus struct {
	Properties struct {
		BlackduckOverallStatus []string `json:"blackduck.overallStatus"`
	} `json:"properties"`
	URI string `json:"uri"`
}
