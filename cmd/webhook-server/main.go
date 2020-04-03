/*
Copyright (c) 2020 Synopsys, Inc.

Added API calls to quay to test policy violations

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

	quayToken := "" // Get this from Quay UI here -> https://docs.quay.io/api/

	fmt.Println("AC webhook: ", pod.Spec.Containers[0].Image)
	image := pod.Spec.Containers[0].Image
	imageSplit := strings.Split(image, ":")

	imageNameSplit := strings.Split(imageSplit[0], "/")
	repoName := imageNameSplit[0]
	orgName := imageNameSplit[1]
	imageName := imageNameSplit[2]
	imageVersion := imageSplit[1]

	fmt.Println(repoName)
	fmt.Println(orgName)
	fmt.Println(imageName)

	url := fmt.Sprintf("http://%s/api/v1/repository/%s/%s/tag?onlyActiveTags=true", repoName, orgName, imageName)
	fmt.Println("AC webhook: looking for SHAs ~> ", url)

	tagDigest := &QuayTagDigest{}
	err := GetResourceOfType(url, quayToken, tagDigest)
	if err != nil {
		fmt.Errorf("AC webhook: Error in getting docker repo: %+v", err)
	} else {
		for _, tagInfo := range tagDigest.Tags {
			if tagInfo.Name == imageVersion {
				sha := strings.Replace(tagInfo.ManifestDigest, "sha256:", "", -1)
				url = fmt.Sprintf("https://%s/api/v1/repository/%s/%s/manifest/sha256:%s/labels", repoName, orgName, imageName, sha)
				fmt.Println("AC webhook: url ~> ", url)

				labels := &QuayLabels{}
				err := GetResourceOfType(url, quayToken, labels)
				if err != nil {
					fmt.Println("AC webhook: Error: ", imageName, ":", sha, " ", err)
				} else {
					fmt.Println("AC webhook: image", imageName, ":", sha, " is an quay image")
					for _, label := range labels.Labels {
						if label.Key == "blackduck.overallstatus" {
							fmt.Println("AC webhook: violation status ~> ", label.Value)
							if label.Value == "IN_VIOLATION" {
								return nil, fmt.Errorf("AC webhook: cannot deploy image ~> Black Duck policy violation in image %s:%s sha256:%s", imageName, tagInfo.Name, sha)
							}
						}
					}
				}
			}
		}
	}

	// Create patch operations to apply sensible defaults, if those options are not set explicitly.
	var patches []patchOperation
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
func GetResourceOfType(url string, quayToken string, target interface{}) error {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("Error in creating get request %e at url %s", err, url)
	}

	if len(quayToken) > 0 {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+quayToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

type QuayLabels struct {
	Labels []struct {
		Value      string `json:"value"`
		MediaType  string `json:"media_type"`
		ID         string `json:"id"`
		Key        string `json:"key"`
		SourceType string `json:"source_type"`
	} `json:"labels"`
}

// QuayTagDigest contains Digest for a particular Quay image
type QuayTagDigest struct {
	HasAdditional bool `json:"has_additional"`
	Page          int  `json:"page"`
	Tags          []struct {
		Name           string `json:"name"`
		Reversion      bool   `json:"reversion"`
		StartTs        int    `json:"start_ts"`
		ImageID        string `json:"image_id"`
		LastModified   string `json:"last_modified"`
		ManifestDigest string `json:"manifest_digest"`
		DockerImageID  string `json:"docker_image_id"`
		IsManifestList bool   `json:"is_manifest_list"`
		Size           int    `json:"size"`
	} `json:"tags"`
}
