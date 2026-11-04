package server

import (
	"github.com/iconidentify/maclab/internal/api"
	"testing"
)

func TestLegacySkippedCoverageCannotQualify(t *testing.T) {
	j := gateJobs("m1air pass")[0]
	j.Spec.Tests = []api.TestSpec{omtSpec()}
	j.Result.Tests = append(j.Result.Tests, api.TestResult{Name: omtTest, Passed: true})
	j.Result.OMT = &api.OMTResult{BaselineJob: "jbase", ComparedTo: "known-good run jbase on good; not compared, as this unattended run skipped what that one passed: video.hevc-on-screen", Skip: 1}
	if omtCompared(j) {
		t.Error("partial unattended comparison still qualifies as compared")
	}
	if why := lessTested(j, true); why == "" {
		t.Error("missing video coverage is invisible to lessTested")
	}
}
