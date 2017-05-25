/*
   Copyright 2017 Red Hat, Inc. and/or its affiliates
   and other contributors.

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

package impl

import (
	"bytes"
	"crypto/tls"
	"fmt"
	//	"sort"
	//	"strconv"
	//	"time"

	hmetrics "github.com/hawkular/hawkular-client-go/metrics"

	"github.com/hawkular/hawkular-openshift-agent/collector"
	"github.com/hawkular/hawkular-openshift-agent/config/security"
	//	"github.com/hawkular/hawkular-openshift-agent/config/tags"
	"github.com/hawkular/hawkular-openshift-agent/http"
	"github.com/hawkular/hawkular-openshift-agent/json"
	"github.com/hawkular/hawkular-openshift-agent/log"
	//	"github.com/hawkular/hawkular-openshift-agent/util/math"
)

type HawkularMetricsCollector struct {
	ID          collector.CollectorID
	Identity    *security.Identity
	Endpoint    *collector.Endpoint
	Environment map[string]string
}

func NewHawkularMetricsCollector(id collector.CollectorID, identity security.Identity, endpoint collector.Endpoint, env map[string]string) (mc *HawkularMetricsCollector) {
	mc = &HawkularMetricsCollector{
		ID:          id,
		Identity:    &identity,
		Endpoint:    &endpoint,
		Environment: env,
	}

	return
}

// GetId implements a method from MetricsCollector interface
func (mc *HawkularMetricsCollector) GetID() collector.CollectorID {
	return mc.ID
}

// GetEndpoint implements a method from MetricsCollector interface
func (mc *HawkularMetricsCollector) GetEndpoint() *collector.Endpoint {
	return mc.Endpoint
}

// GetAdditionalEnvironment implements a method from MetricsCollector interface
func (mc *HawkularMetricsCollector) GetAdditionalEnvironment() map[string]string {
	return mc.Environment
}

// CollectMetrics does the real work of actually connecting to a remote Hawkular agent endpoint
// and collects all metrics it find there, and returns those metrics.
// CollectMetrics implements a method from MetricsCollector interface
func (mc *HawkularMetricsCollector) CollectMetrics() (metrics []hmetrics.MetricHeader, err error) {

	url := mc.Endpoint.URL

	httpConfig := http.HttpClientConfig{
		Identity: mc.Identity,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: mc.Endpoint.TLS.Skip_Certificate_Validation,
		},
	}
	httpClient, err := httpConfig.BuildHttpClient()
	if err != nil {
		err = fmt.Errorf("Failed to create http client for Hawkular endpoint [%v]. err=%v", url, err)
		return
	}

	// Get the Hawkular endpoint data
	jsonData, err := json.Scrape(url, &mc.Endpoint.Credentials, httpClient)
	if err != nil {
		return
	}

	// Listen to a channel that will receive all the metrics so we can store them in our metrics array.
	metrics = make([]hmetrics.MetricHeader, 0)

	for k, v := range jsonData {
		mc.processHawkular(k, v)
	}

	if log.IsTrace() {
		var buffer bytes.Buffer
		n := 0
		buffer.WriteString(fmt.Sprintf("Hawkular metrics collected from endpoint [%v]:\n", url))
		for _, m := range metrics {
			buffer.WriteString(fmt.Sprintf("%v\n", m))
			n += len(m.Data)
		}
		buffer.WriteString(fmt.Sprintf("==TOTAL HAWKULAR METRICS COLLECTED=%v\n", n))
		log.Trace(buffer.String())
	}

	return
}

// CollectMetricDetails implements a method from MetricsCollector interface
func (mc *HawkularMetricsCollector) CollectMetricDetails(metricNames []string) ([]collector.MetricDetails, error) {
	// json does not provide this information
	return make([]collector.MetricDetails, 0), nil
}

func (mc *HawkularMetricsCollector) processHawkular(jsonName string, jsonValue interface{}) {

	url := mc.Endpoint.URL

	switch vv := jsonValue.(type) {

	case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:

	case string:

	case bool:

	case []interface{}:

	case map[string]interface{}:

	default:
		log.Debugf("Hawkular collector cannot process the type [%T] for [%v]. url=[%v]", vv, jsonName, url)
	}
}
