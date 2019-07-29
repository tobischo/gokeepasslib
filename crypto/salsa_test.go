package crypto

// import "testing"

// func TestCompareSalsaPack(t *testing.T) {
// 	cases := []struct {
// 		title  string
// 		key    []byte
// 		values []string
// 	}{
// 		{
// 			title: "values",
// 			key: []byte{
// 				34, 57, 70, 73,
// 				217, 238, 218, 69,
// 				206, 187, 238, 51,
// 				195, 251, 68, 36,
// 				90, 153, 42, 227,
// 				124, 69, 236, 91,
// 				214, 48, 61, 195,
// 				1, 190, 118, 0,
// 			},
// 			values: []string{
// 				"john_dough",
// 				"asdasdas",
// 				"asfsdfsdff",
// 				"abcdefghijklmnopqrstuvwxyz",
// 				"abcdefghijklmnopqrstuvwxyz",
// 				"abcdefghijklmnopqrstuvwxyz",
// 			},
// 		},
// 	}

// 	for _, c := range cases {
// 		t.Run(c.title, func(t *testing.T) {
// 			salsa1, _ := NewSalsaStream(c.key)
// 			salsa2 := NewSalsaStream2(c.key)

// 			for _, value := range c.values {
// 				packed1 := salsa1.Pack([]byte(value))
// 				packed2 := salsa2.Pack([]byte(value))

// 				if packed1 != packed2 {
// 					t.Errorf("Value 1 '%s' is not identical to value 2 '%s'", packed1, packed2)
// 				}
// 			}
// 		})
// 	}
// }

// func TestCompareSalsaUnpack(t *testing.T) {
// 	cases := []struct {
// 		title  string
// 		key    []byte
// 		values []string
// 	}{
// 		{
// 			title: "values",
// 			key: []byte{
// 				34, 57, 70, 73,
// 				217, 238, 218, 69,
// 				206, 187, 238, 51,
// 				195, 251, 68, 36,
// 				90, 153, 42, 227,
// 				124, 69, 236, 91,
// 				214, 48, 61, 195,
// 				1, 190, 118, 0,
// 			},
// 			values: []string{
// 				"LTArva43LSJy/g==",
// 				"I5wA89NZow0=",
// 				"tac4jMhch0Ikbw==",
// 			},
// 		},
// 	}

// 	for _, c := range cases {
// 		t.Run(c.title, func(t *testing.T) {
// 			salsa1, _ := NewSalsaStream(c.key)
// 			salsa2 := NewSalsaStream2(c.key)

// 			for _, value := range c.values {
// 				unpacked1 := salsa1.Unpack(value)
// 				unpacked2 := salsa2.Unpack(value)

// 				if string(unpacked1) != string(unpacked2) {
// 					t.Errorf("Value 1 '%s' is not identical to value 2 '%s'", unpacked1, unpacked2)
// 				}
// 			}
// 		})
// 	}
// }
