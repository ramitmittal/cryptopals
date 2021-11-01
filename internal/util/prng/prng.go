package prng

const (
	n                 = 624
	m                 = 397
	a                 = 0x9908B0DF
	lower_mask uint32 = (1 << r) - 1
	upper_mask uint32 = (^lower_mask)
	f          uint32 = 1812433253
	w                 = 32
	r                 = 31
	u                 = 11
	d                 = 0xFFFFFFFF
	s                 = 7
	b                 = 0x9D2C5680
	t                 = 15
	c                 = 0xEFC60000
	l                 = 18
)

var (
	mag01 = [2]uint32{0, a}
)

type Twister struct {
	Mt    [n]uint32
	Index int
}

func New(seed uint32) *Twister {
	tw := Twister{}
	tw.Mt[0] = seed

	for i := 1; i < n; i++ {
		x := (tw.Mt[i-1] ^ (tw.Mt[i-1] >> (w - 2)))
		tw.Mt[i] = uint32(f*x) + uint32(i)
	}

	tw.twist()

	return &tw
}

func (tw *Twister) twist() {
	var i int
	for i = 0; i < n-m; i++ {
		y := tw.Mt[i]&upper_mask | tw.Mt[i+1]&lower_mask
		tw.Mt[i] = tw.Mt[i+m] ^ (y >> 1) ^ mag01[y&1]
	}
	for ; i < n-1; i++ {
		y := tw.Mt[i]&upper_mask | tw.Mt[i+1]&lower_mask
		tw.Mt[i] = tw.Mt[i+m-n] ^ (y >> 1) ^ mag01[y&1]
	}
	y := tw.Mt[n-1]&upper_mask | tw.Mt[0]&lower_mask
	tw.Mt[n-1] = tw.Mt[m-1] ^ (y >> 1) ^ mag01[y&1]

	tw.Index = 0
}

func (tw *Twister) ExtractNumber() uint32 {
	if tw.Index == n {
		tw.twist()
	}

	y := tw.Mt[tw.Index]
	y = y ^ (y >> u)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)

	tw.Index = tw.Index + 1
	return y
}
