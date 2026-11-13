package enroll

import "testing"

func TestJoinCodeRoundTrip(t *testing.T) {
	want := JoinCode{
		ServerAddress: "203.0.113.1:443", NetworkName: "home", ServerName: "www.speedtest.cn",
		OverlayPool: "10.91.0.0/24", HomeNode: "home", HomeSubnet: "192.168.3.0/24",
	}
	encoded, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
}
