// Package huffman implements Blizzard's adaptive Huffman codec used by
// MPQ archives. It is a port of stormlib/src/huffman/huff.cpp.
//
// Huffman is rarely used standalone; it is normally combined with ADPCM
// compression on WAVE files. Both compress and decompress are implemented to
// allow round-trip testing without requiring fixture files.
package huffman

import "errors"

// Errors returned by Decompress.
var (
	ErrEmptyOutput   = errors.New("huffman: zero-length output requested")
	ErrTruncated     = errors.New("huffman: truncated input")
	ErrInvalidType   = errors.New("huffman: invalid data type")
	ErrItemOverflow  = errors.New("huffman: tree item buffer exhausted")
	ErrDecodeFailure = errors.New("huffman: decode failure")
)

const (
	huffItemCount       = 0x203
	linkItemCount       = 0x80
	huffDecompressError = 0x1FF
	maxDataType         = 9

	// Data type 0 in the StormLib source.
	dataTypeSparse = 0
)

type insertPoint int

const (
	insertAfter insertPoint = iota
	insertBefore
)

type treeItem struct {
	next, prev        *treeItem
	decompressedValue uint32
	weight            uint32
	parent            *treeItem
	childLo           *treeItem
}

type quickLink struct {
	validValue        uint32
	validBits         uint32
	decompressedValue uint32
	item              *treeItem
}

type tree struct {
	itemBuffer    [huffItemCount]treeItem
	listHead      treeItem
	quickLinks    [linkItemCount]quickLink
	itemsByByte   [0x102]*treeItem
	minValidValue uint32
	itemsUsed     int
	isSparseData  bool
}

func newTree(forCompression bool) *tree {
	t := &tree{minValidValue: 1}
	t.listHead.next = &t.listHead
	t.listHead.prev = &t.listHead
	_ = forCompression

	return t
}

func (t *tree) head() *treeItem { return &t.listHead }

// removeItem removes the item from the doubly-linked list.
func removeItem(it *treeItem) {
	if it.next != nil {
		it.prev.next = it.next
		it.next.prev = it.prev
		it.next = nil
		it.prev = nil
	}
}

// linkTwoItems inserts pItem2 immediately AFTER pItem1.
func linkTwoItems(a, b *treeItem) {
	b.next = a.next
	b.prev = a.next.prev
	a.next.prev = b
	a.next = b
}

func (t *tree) insertItem(it *treeItem, ip insertPoint, anchor *treeItem) {
	removeItem(it)

	if anchor == nil {
		anchor = t.head()
	}

	switch ip {
	case insertAfter:
		linkTwoItems(anchor, it)
	case insertBefore:
		linkTwoItems(anchor.prev, it)
	}
}

func (t *tree) findHigherOrEqualItem(start *treeItem, weight uint32) *treeItem {
	if start != nil {
		for start != t.head() {
			if start.weight >= weight {
				return start
			}

			start = start.prev
		}
	}

	return t.head()
}

func (t *tree) createNewItem(value, weight uint32, ip insertPoint) *treeItem {
	if t.itemsUsed >= huffItemCount {
		return nil
	}

	it := &t.itemBuffer[t.itemsUsed]
	t.itemsUsed++
	t.insertItem(it, ip, nil)
	it.decompressedValue = value
	it.weight = weight
	it.parent = nil
	it.childLo = nil

	return it
}

func (t *tree) fixupItemPosByWeight(it *treeItem, maxWeight uint32) uint32 {
	if it.weight < maxWeight {
		higher := t.findHigherOrEqualItem(t.listHead.prev, it.weight)
		removeItem(it)
		linkTwoItems(higher, it)
	} else {
		maxWeight = it.weight
	}

	return maxWeight
}

func (t *tree) buildTree(dataType uint32) bool {
	for i := range t.itemsByByte {
		t.itemsByByte[i] = nil
	}

	maxWeight := uint32(0)

	dataType &= 0x0F
	if dataType >= maxDataType {
		return false
	}

	table := dataDistributions[dataType]

	for i := 0; i < 0x100; i++ {
		w := uint32(table[i])
		if w != 0 {
			it := t.createNewItem(uint32(i), w, insertAfter)
			if it == nil {
				return false
			}

			t.itemsByByte[i] = it
			maxWeight = t.fixupItemPosByWeight(it, maxWeight)
		}
	}

	t.itemsByByte[0x100] = t.createNewItem(0x100, 1, insertBefore)

	t.itemsByByte[0x101] = t.createNewItem(0x101, 1, insertBefore)
	if t.itemsByByte[0x100] == nil || t.itemsByByte[0x101] == nil {
		return false
	}

	childLo := t.listHead.prev
	for childLo != t.head() {
		childHi := childLo.prev
		if childHi == t.head() {
			break
		}

		parent := t.createNewItem(0, childHi.weight+childLo.weight, insertAfter)
		if parent == nil {
			return false
		}

		childLo.parent = parent
		childHi.parent = parent
		parent.childLo = childLo
		maxWeight = t.fixupItemPosByWeight(parent, maxWeight)
		childLo = childHi.prev
	}

	t.minValidValue = 1
	for i := range t.quickLinks {
		t.quickLinks[i] = quickLink{}
	}

	return true
}

func (t *tree) incWeightsAndRebalance(item *treeItem) {
	for it := item; it != nil; it = it.parent {
		it.weight++

		higher := t.findHigherOrEqualItem(it.prev, it.weight)
		childHi := higher.next

		if childHi != it {
			removeItem(childHi)
			linkTwoItems(it, childHi)
			removeItem(it)
			linkTwoItems(higher, it)

			childLo := childHi.parent.childLo

			parent := it.parent
			if parent.childLo == it {
				parent.childLo = childHi
			}

			if childLo == childHi {
				childHi.parent.childLo = it
			}

			parent = it.parent
			it.parent = childHi.parent
			childHi.parent = parent

			t.minValidValue++
		}
	}
}

func (t *tree) insertNewBranchAndRebalance(value1, value2 uint32) bool {
	last := t.listHead.prev

	hi := t.createNewItem(value1, last.weight, insertBefore)
	if hi == nil {
		return false
	}

	hi.parent = last
	t.itemsByByte[value1] = hi

	lo := t.createNewItem(value2, 0, insertBefore)
	if lo == nil {
		return false
	}

	lo.parent = last
	last.childLo = lo
	t.itemsByByte[value2] = lo

	t.incWeightsAndRebalance(lo)

	return true
}

// ---------------------------------------------------------------------------
// Bit I/O

type bitReader struct {
	buf       []byte
	pos       int
	bitBuffer uint32
	bitCount  uint32
}

func (r *bitReader) get1Bit() (uint32, bool) {
	if r.bitCount == 0 {
		if r.pos >= len(r.buf) {
			return 0, false
		}

		r.bitBuffer = uint32(r.buf[r.pos])
		r.pos++
		r.bitCount = 8
	}

	v := r.bitBuffer & 1
	r.bitBuffer >>= 1
	r.bitCount--

	return v, true
}

func (r *bitReader) get8Bits() (uint32, bool) {
	if r.bitCount < 8 {
		if r.pos >= len(r.buf) {
			return 0, false
		}

		reload := uint32(r.buf[r.pos])
		r.pos++
		r.bitBuffer |= reload << r.bitCount
		r.bitCount += 8
	}

	v := r.bitBuffer & 0xFF
	r.bitBuffer >>= 8
	r.bitCount -= 8

	return v, true
}

func (r *bitReader) peek7Bits() (uint32, bool) {
	if r.bitCount < 7 {
		if r.pos >= len(r.buf) {
			return 0, false
		}

		reload := uint32(r.buf[r.pos])
		r.pos++
		r.bitBuffer |= reload << r.bitCount
		r.bitCount += 8
	}

	return r.bitBuffer & 0x7F, true
}

func (r *bitReader) skipBits(n uint32) {
	if r.bitCount < n {
		if r.pos >= len(r.buf) {
			return
		}

		reload := uint32(r.buf[r.pos])
		r.pos++
		r.bitBuffer |= reload << r.bitCount
		r.bitCount += 8
	}

	r.bitBuffer >>= n
	r.bitCount -= n
}

type bitWriter struct {
	buf       []byte
	bitBuffer uint32
	bitCount  uint32
}

func (w *bitWriter) putBits(value, n uint32) {
	w.bitBuffer |= value << w.bitCount

	w.bitCount += n
	for w.bitCount >= 8 {
		w.buf = append(w.buf, byte(w.bitBuffer&0xFF))
		w.bitBuffer >>= 8
		w.bitCount -= 8
	}
}

func (w *bitWriter) flush() {
	for w.bitCount != 0 {
		w.buf = append(w.buf, byte(w.bitBuffer&0xFF))

		w.bitBuffer >>= 8
		if w.bitCount > 8 {
			w.bitCount -= 8
		} else {
			w.bitCount = 0
		}
	}
}

// ---------------------------------------------------------------------------
// Codec entry points

func (t *tree) decodeOneByte(r *bitReader) uint32 {
	var (
		pItemLink *treeItem
		pItem     *treeItem
		bitCount  uint32
	)

	idx, hasIdx := r.peek7Bits()
	if hasIdx && t.quickLinks[idx].validValue > t.minValidValue {
		if t.quickLinks[idx].validBits <= 7 {
			r.skipBits(t.quickLinks[idx].validBits)
			return t.quickLinks[idx].decompressedValue
		}

		pItem = t.quickLinks[idx].item

		r.skipBits(7)
	} else {
		if t.listHead.next == t.head() {
			return huffDecompressError
		}

		pItem = t.listHead.next
	}

	for pItem.childLo != nil {
		bit, ok := r.get1Bit()
		if !ok {
			return huffDecompressError
		}

		if bit != 0 {
			pItem = pItem.childLo.prev
		} else {
			pItem = pItem.childLo
		}

		bitCount++
		if bitCount == 7 {
			pItemLink = pItem
		}
	}

	if hasIdx && t.quickLinks[idx].validValue < t.minValidValue {
		if bitCount > 7 {
			t.quickLinks[idx].validValue = t.minValidValue
			t.quickLinks[idx].validBits = bitCount
			t.quickLinks[idx].item = pItemLink
		} else {
			var cur uint32
			if bitCount != 0 {
				cur = idx & (0xFFFFFFFF >> (32 - bitCount))
			} else {
				cur = 0
			}

			for cur < linkItemCount {
				t.quickLinks[cur].validValue = t.minValidValue
				t.quickLinks[cur].validBits = bitCount
				t.quickLinks[cur].decompressedValue = pItem.decompressedValue

				if bitCount == 0 {
					break
				}

				cur += 1 << bitCount
			}
		}
	}

	return pItem.decompressedValue
}

func (t *tree) encodeOneByte(w *bitWriter, item *treeItem) {
	parent := item.parent

	var bitBuffer, bitCount uint32

	for parent != nil {
		var bit uint32
		if parent.childLo != item {
			bit = 1
		}

		bitBuffer = (bitBuffer << 1) | bit
		bitCount++
		item = parent
		parent = parent.parent
	}

	w.putBits(bitBuffer, bitCount)
}

// Decompress reverses Blizzard's adaptive Huffman codec on src.
// expectedLen is the maximum number of decompressed bytes produced.
func Decompress(src []byte, expectedLen int) ([]byte, error) {
	if expectedLen == 0 {
		return nil, ErrEmptyOutput
	}

	r := &bitReader{buf: src}

	dataType, ok := r.get8Bits()
	if !ok {
		return nil, ErrTruncated
	}

	t := newTree(false)

	t.isSparseData = dataType == dataTypeSparse
	if !t.buildTree(dataType) {
		return nil, ErrInvalidType
	}

	out := make([]byte, 0, expectedLen)

	for {
		v := t.decodeOneByte(r)
		if v == 0x100 {
			break
		}

		if v == huffDecompressError {
			return nil, ErrDecodeFailure
		}

		if v == 0x101 {
			nv, ok := r.get8Bits()
			if !ok {
				return nil, ErrTruncated
			}

			v = nv
			if !t.insertNewBranchAndRebalance(t.listHead.prev.decompressedValue, v) {
				return nil, ErrItemOverflow
			}

			if !t.isSparseData {
				t.incWeightsAndRebalance(t.itemsByByte[v])
			}
		}

		if len(out) >= expectedLen {
			break
		}

		out = append(out, byte(v))
		if t.isSparseData {
			t.incWeightsAndRebalance(t.itemsByByte[v])
		}
	}

	return out, nil
}

// Compress mirrors Blizzard's adaptive Huffman encoder. Used for round-trip
// testing; the public archive write path may rely on it later.
func Compress(src []byte, dataType uint32) ([]byte, error) {
	t := newTree(true)
	if !t.buildTree(dataType) {
		return nil, ErrInvalidType
	}

	t.isSparseData = dataType == dataTypeSparse

	w := &bitWriter{}
	w.putBits(dataType&0xFF, 8)

	for _, b := range src {
		v := uint32(b)
		if t.itemsByByte[v] == nil {
			t.encodeOneByte(w, t.itemsByByte[0x101])
			w.putBits(v, 8)

			if !t.insertNewBranchAndRebalance(t.listHead.prev.decompressedValue, v) {
				return nil, ErrItemOverflow
			}

			if t.isSparseData {
				t.incWeightsAndRebalance(t.itemsByByte[v])
				continue
			}

			t.incWeightsAndRebalance(t.itemsByByte[v])
		} else {
			t.encodeOneByte(w, t.itemsByByte[v])
		}

		if t.isSparseData {
			t.incWeightsAndRebalance(t.itemsByByte[v])
		}
	}

	t.encodeOneByte(w, t.itemsByByte[0x100])
	w.flush()

	return w.buf, nil
}
