package prog

import (
	"testing"
)

func TestBlacklist(t *testing.T) {
	tests := []struct {
		pstr   string
		result bool
	}{
		{
			"1000:mmap(&(0x7f0000000000/0x6000)=nil, (0x6000), 0x3, 0x32, 0xffffffffffffffff, 0x0)" +
				"1001:r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x16042, 0x1b6)" +
				"1000:write(r0, &(0x7f0000004000)=\"71\", 0x1)",
			true,
		},
		{
			"1000:mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)" +
				"1000:mmap(&(0x7f0000001000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)" +
				"1000:r0 = creat(&(0x7f0000001000)=\"2e2f66696c653000\", 0xfffffffffffffffc)" +
				"1000:lseek(r0, 0xff00000000000000, 0x4)",
			false,
		},
	}

	for ti, test := range tests {
		p, err := Deserialize([]byte(test.pstr))
		if err != nil {
			t.Fatalf("fail to deserialize program")
		}
		if Blacklist(p) != test.result {
			t.Fatalf("#%v: wrong result", ti)
		}
	}

}
