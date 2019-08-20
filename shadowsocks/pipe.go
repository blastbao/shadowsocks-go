package shadowsocks

import (
	"net"
	"time"
)

func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn, addTraffic func(int)) {
	defer dst.Close()

	// 从字节池中取出 buf
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)

	// 不断的从 src 读取数据并写入到 dst
	for {
		// 设置读取超时
		SetReadTimeout(src)
		// 读取不定长数据到 buf 中，返回读取的字节数 n
		n, err := src.Read(buf)
		// 若统计读取字节总数的函数 addTraffic 不空，则调用它
		if addTraffic != nil {
			addTraffic(n)
		}

		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				// 出错则 break 退出循环
				Debug.Println("write:", err)
				break
			}
		}


		// 出错则 break 退出循环
		if err != nil {

			//Always "use of closed network connection",
			//but no easy way to identify this specific error.
			//So just leave the error along for now.
			//More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/

			break
		}
	}
	return
}
