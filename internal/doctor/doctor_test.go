package doctor

import (
	"strings"
	"testing"
	"time"
)

func TestSkewStep(t *testing.T) {
	local := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	if s := skewStep("20261007120200.0Z", local); !s.OK {
		t.Errorf("2 min skew failed: %+v", s)
	}
	if s := skewStep("20261007121000.0Z", local); s.OK || !strings.Contains(s.Cause, "5 minutes") {
		t.Errorf("10 min skew passed: %+v", s)
	}
	if s := skewStep("", local); !s.OK {
		t.Errorf("missing currentTime must not fail: %+v", s)
	}
}

func TestDescribeRoot(t *testing.T) {
	if got := describeRoot(map[string]string{"vendorName": "Samba Team", "vendorVersion": "4.19", "defaultNamingContext": "DC=lab"}); got != "Samba AD DC 4.19, DC=lab" {
		t.Error(got)
	}
	if got := describeRoot(map[string]string{"domainControllerFunctionality": "10"}); !strings.Contains(got, "Active Directory") {
		t.Error(got)
	}
}
