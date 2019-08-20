// Provides leaky buffer, based on the example in Effective Go.
package shadowsocks



type LeakyBuf struct {
	bufSize  int // size of each buffer
	freeList chan []byte
}

const leakyBufSize = 4108 // data.len(2) + hmacsha1(10) + data(4096)
const maxNBuf = 2048

var leakyBuf = NewLeakyBuf(maxNBuf, leakyBufSize)

// NewLeakyBuf creates a leaky buffer which can hold at most n buffer,
// each with bufSize bytes.
func NewLeakyBuf(n, bufSize int) *LeakyBuf {
	return &LeakyBuf{
		bufSize:  bufSize,              // 每个 []byte 切片大小为 bufSize 个字节
		freeList: make(chan []byte, n), // 创建容纳 n 个 []byte 切片的 channel
	}
}

// Get returns a buffer from the leaky buffer or create a new buffer.
func (lb *LeakyBuf) Get() (b []byte) {
	select {
	case b = <-lb.freeList: // 如果空闲队列不空，则从中取出一个字节切片
	default:
		b = make([]byte, lb.bufSize) // 否则，new 一个
	}
	return
}

// Put add the buffer into the free buffer pool for reuse. Panic if the buffer
// size is not the same with the leaky buffer's. This is intended to expose
// error usage of leaky buffer.
func (lb *LeakyBuf) Put(b []byte) {

	// 参数校验，只接受大小为 bufSize 的切片
	if len(b) != lb.bufSize {
		panic("invalid buffer size that's put into leaky buffer")
	}
	select {
	case lb.freeList <- b: //如果空闲队列不满，就塞进去
	default: // 否则，就什么都不做，让系统 gc 来回收
	}
	return
}
