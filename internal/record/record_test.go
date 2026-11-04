package record

import (
	"encoding/json"
	"testing"
)

func TestLegacyTalkerAndPID(t *testing.T) {
	var s Sample
	in := `{"ts":"2026-11-03T10:00:00","gw":{"avg":2.1,"max":3.0,"loss":0},"net":null,
	        "in_kBps":12,"out_kBps":3,"top":[{"proc":"com.example.agent.123","in_kbps":10,"out_kbps":2}]}`
	if err := json.Unmarshal([]byte(in), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Top) != 1 || s.Top[0].Proc != "com.example.agent" || s.Top[0].PID != 123 || s.Top[0].InKBps != 10 {
		t.Fatalf("legacy talker not decoded: %+v", s.Top)
	}
	var e Event
	if err := json.Unmarshal([]byte(`{"ts":"x","event":"NEW_NET_APP","proc":"curl","pid":"4242"}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.PID != 4242 {
		t.Fatalf("string pid not decoded: %v", e.PID)
	}
}

func TestEventOmitsUnusedFields(t *testing.T) {
	b, err := json.Marshal(Event{TS: "t", Event: Recovered})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ts":"t","event":"RECOVERED"}` {
		t.Fatalf("unexpected encoding: %s", b)
	}
}
