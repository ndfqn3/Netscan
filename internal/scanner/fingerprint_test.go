package scanner

import (
	"regexp"
	"testing"
)

func TestCMSRulesRegexValid(t *testing.T) {
	for _, rule := range cmsRules {
		for _, re := range rule.BodyRe {
			if _, err := regexp.Compile(re); err != nil {
				t.Errorf("CMS %s 非法 BodyRe 正则 %q: %v", rule.Name, re, err)
			}
		}
		if rule.VersionRe != "" {
			if _, err := regexp.Compile(rule.VersionRe); err != nil {
				t.Errorf("CMS %s 非法 VersionRe 正则 %q: %v", rule.Name, rule.VersionRe, err)
			}
		}
	}
}
