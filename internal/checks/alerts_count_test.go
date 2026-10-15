package checks_test

import (
	"testing"
	"time"

	"github.com/prometheus/common/model"

	"github.com/cloudflare/pint/internal/checks"
	"github.com/cloudflare/pint/internal/promapi"
)

func newAlertsCheck(prom *promapi.FailoverGroup) checks.RuleChecker {
	return checks.NewAlertsCheck(prom, time.Hour*24, time.Minute, time.Minute*5, 0, "", checks.Information)
}

func TestAlertsCountCheck(t *testing.T) {
	content := "- alert: Foo Is Down\n  expr: up{job=\"foo\"} == 0\n"
	// Cases that sit right on a boundary use a single timestamp, so that samples
	// generated a second apart can't move them across it.
	now := time.Now()

	testCases := []checkTest{
		{
			description: "ignores recording rules",
			content:     "- record: foo\n  expr: up == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
		},
		{
			description: "ignores rules with syntax errors",
			content:     "- alert: Foo Is Down\n  expr: sum(\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
		},
		{
			description: "bad request",
			content:     content,
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: respondWithBadData(),
				},
			},
			problems: true,
		},
		{
			description: "connection refused / upstream not required / warning",
			content:     content,
			checker:     newAlertsCheck,
			prometheus: func(_ string) *promapi.FailoverGroup {
				return simpleProm("prom", "http://127.0.0.1:1111", time.Second*5, false)
			},
			problems: true,
		},
		{
			description: "empty response",
			content:     content,
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: respondWithEmptyMatrix(),
				},
			},
			problems: true,
		},
		{
			description: "multiple alerts",
			content:     content,
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							// 7m
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-24),
								time.Now().Add(time.Hour*-24).Add(time.Minute*6),
								time.Minute,
							),
							// 7m
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							// 2m
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute),
								time.Minute,
							),
							// 17m
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute*16),
								time.Minute,
							),
							// 37m
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*36),
								time.Minute,
							),
							// 37m
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-19),
								time.Now().Add(time.Hour*-19).Add(time.Minute*36),
								time.Minute,
							),
							// 2h1m
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-10),
								time.Now().Add(time.Hour*-10).Add(time.Hour*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			description: "for: 10m",
			content:     "- alert: Foo Is Down\n  for: 10m\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-24),
								time.Now().Add(time.Hour*-24).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute*16),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*9).Add(time.Second*59),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-18),
								time.Now().Add(time.Hour*-18).Add(time.Hour*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			description: "minCount=2",
			content:     "- alert: Foo Is Down\n  for: 10m\n  expr: up{job=\"foo\"} == 0\n",
			checker: func(prom *promapi.FailoverGroup) checks.RuleChecker {
				return checks.NewAlertsCheck(prom, time.Hour*24, time.Minute, time.Minute*5, 2, "rule comment", checks.Information)
			},
			prometheus: newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-24),
								time.Now().Add(time.Hour*-24).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute*16),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*9).Add(time.Second*59),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-18),
								time.Now().Add(time.Hour*-18).Add(time.Hour*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			description: "minCount=2 severity=bug",
			content:     "- alert: Foo Is Down\n  for: 10m\n  expr: up{job=\"foo\"} == 0\n",
			checker: func(prom *promapi.FailoverGroup) checks.RuleChecker {
				return checks.NewAlertsCheck(prom, time.Hour*24, time.Minute, time.Minute*5, 2, "", checks.Bug)
			},
			prometheus: newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-24),
								time.Now().Add(time.Hour*-24).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute*16),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*9).Add(time.Second*59),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-18),
								time.Now().Add(time.Hour*-18).Add(time.Hour*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			description: "minCount=10",
			content:     "- alert: Foo Is Down\n  for: 10m\n  expr: up{job=\"foo\"} == 0\n",
			checker: func(prom *promapi.FailoverGroup) checks.RuleChecker {
				return checks.NewAlertsCheck(prom, time.Hour*24, time.Minute, time.Minute*5, 10, "", checks.Information)
			},
			prometheus: newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-24),
								time.Now().Add(time.Hour*-24).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute*16),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*9).Add(time.Second*59),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-18),
								time.Now().Add(time.Hour*-18).Add(time.Hour*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
		},
		{
			description: "{__name__=}",
			content: `
- alert: foo
  expr: '{__name__="up", job="foo"} == 0'
`,
			checker:    newAlertsCheck,
			prometheus: newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `{__name__="up", job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			description: "{__name__=~}",
			content: `
- alert: foo
  expr: '{__name__=~"(up|foo)", job="foo"} == 0'
`,
			checker:    newAlertsCheck,
			prometheus: newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `{__name__=~"(up|foo)", job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute*16),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*9).Add(time.Second*59),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-10),
								time.Now().Add(time.Hour*-10).Add(time.Hour*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			description: "uptime query error",
			content:     "- alert: Foo Is Down\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithInternalError(),
				},
			},
			problems: true,
		},
		{
			description: "keep_firing_for: 10m",
			content:     "- alert: Foo Is Down\n  keep_firing_for: 10m\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-24),
								time.Now().Add(time.Hour*-24).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute*16),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*9).Add(time.Second*59),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-18),
								time.Now().Add(time.Hour*-18).Add(time.Hour*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			description: "for: 10m + keep_firing_for: 10m",
			content:     "- alert: Foo Is Down\n  for: 10m\n  keep_firing_for: 10m\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-24),
								time.Now().Add(time.Hour*-24).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-23),
								time.Now().Add(time.Hour*-23).Add(time.Minute*6),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-22),
								time.Now().Add(time.Hour*-22).Add(time.Minute),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-21),
								time.Now().Add(time.Hour*-21).Add(time.Minute*16),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*9).Add(time.Second*59),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-18),
								time.Now().Add(time.Hour*-18).Add(time.Hour*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			// keep_firing_for doesn't delay an alert, it keeps it firing after the query
			// stops returning results. Three 5m bursts 15m apart are a single alert that
			// keeps firing between bursts, a burst 4h later is a second one.
			description: "keep_firing_for: 30m merges bursts",
			content:     "- alert: Foo Is Down\n  keep_firing_for: 30m\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*5),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20).Add(time.Minute*20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*25),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20).Add(time.Minute*40),
								time.Now().Add(time.Hour*-20).Add(time.Minute*45),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-16),
								time.Now().Add(time.Hour*-16).Add(time.Minute*5),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: respondWithSingleRangeVector1D(),
				},
			},
			problems: true,
		},
		{
			// The query stops returning results for two evaluations, which keep_firing_for: 2m
			// covers, so it's one alert. Three missed evaluations end the alert.
			description: "keep_firing_for: 2m boundary",
			content:     "- alert: Foo Is Down\n  keep_firing_for: 2m\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "foo"},
								now.Add(time.Hour*-20),
								now.Add(time.Hour*-20),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								now.Add(time.Hour*-20).Add(time.Minute*3),
								now.Add(time.Hour*-20).Add(time.Minute*3),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								now.Add(time.Hour*-19),
								now.Add(time.Hour*-19),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								now.Add(time.Hour*-19).Add(time.Minute*4),
								now.Add(time.Hour*-19).Add(time.Minute*4),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					// Prometheus is up for every step, so any missing step is a real gap.
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{},
								now.Add(time.Hour*-24),
								now,
								time.Minute,
							),
						},
					},
				},
			},
			problems: true,
		},
		{
			// A range too short for `for` still continues an alert that keeps firing, and
			// extends it, so the 15m range at +70m is still the same alert. A short range
			// that doesn't follow a firing alert isn't one, and each series is counted on its own.
			description: "for: 10m + keep_firing_for: 30m continues with short ranges",
			content:     "- alert: Foo Is Down\n  for: 10m\n  keep_firing_for: 30m\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{"job": "bar"},
								now.Add(time.Hour*-20),
								now.Add(time.Hour*-20).Add(time.Minute*15),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								now.Add(time.Hour*-20),
								now.Add(time.Hour*-20).Add(time.Minute*15),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								now.Add(time.Hour*-20).Add(time.Minute*40),
								now.Add(time.Hour*-20).Add(time.Minute*42),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								now.Add(time.Hour*-20).Add(time.Minute*70),
								now.Add(time.Hour*-20).Add(time.Minute*85),
								time.Minute,
							),
							generateSampleStream(
								map[string]string{"job": "foo"},
								now.Add(time.Hour*-16),
								now.Add(time.Hour*-16).Add(time.Minute*2),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					// Prometheus is up for every step, so any missing step is a real gap.
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{},
								now.Add(time.Hour*-24),
								now,
								time.Minute,
							),
						},
					},
				},
			},
			problems: true,
		},
		{
			// Two 7m ranges separated by 3m, Prometheus was down during those 3m.
			// Since Prometheus was down there's no gap, so ranges merge into ~17m, exceeding for: 10m.
			description: "ranges merge when separated by Prometheus downtime",
			content:     "- alert: Foo Is Down\n  for: 10m\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							// 7m range starting at -20h
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*6),
								time.Minute,
							),
							// 7m range starting at -20h+10m (3m gap between ranges)
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20).Add(time.Minute*10),
								time.Now().Add(time.Hour*-20).Add(time.Minute*16),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							// Uptime from -24h to -20h+6m (covers first range)
							generateSampleStream(
								map[string]string{},
								time.Now().Add(time.Hour*-24),
								time.Now().Add(time.Hour*-20).Add(time.Minute*6),
								time.Minute,
							),
							// Uptime from -20h+10m to now (covers second range)
							// Prometheus was down from -20h+6m to -20h+10m
							generateSampleStream(
								map[string]string{},
								time.Now().Add(time.Hour*-20).Add(time.Minute*10),
								time.Now(),
								time.Minute,
							),
						},
					},
				},
			},
			problems: true,
		},
		{
			// Two 7m ranges but Prometheus was up the entire time.
			// There's a gap between them, so they don't merge.
			description: "ranges stay separate when gap is confirmed by uptime",
			content:     "- alert: Foo Is Down\n  for: 10m\n  expr: up{job=\"foo\"} == 0\n",
			checker:     newAlertsCheck,
			prometheus:  newSimpleProm,
			mocks: []*prometheusMock{
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: `up{job="foo"} == 0`},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							// 7m range starting at -20h
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20),
								time.Now().Add(time.Hour*-20).Add(time.Minute*6),
								time.Minute,
							),
							// 7m range starting at -20h+10m (3m gap between ranges)
							generateSampleStream(
								map[string]string{"job": "foo"},
								time.Now().Add(time.Hour*-20).Add(time.Minute*10),
								time.Now().Add(time.Hour*-20).Add(time.Minute*16),
								time.Minute,
							),
						},
					},
				},
				{
					conds: []requestCondition{
						requireRangeQueryPath,
						formCond{key: "query", value: "count(\nup\n)"},
					},
					resp: matrixResponse{
						samples: []*model.SampleStream{
							generateSampleStream(
								map[string]string{},
								time.Now().Add(time.Hour*-24),
								time.Now(),
								time.Minute,
							),
						},
					},
				},
			},
			problems: true,
		},
	}

	runTests(t, testCases)
}
