package literalmatch

import (
	"context"
	"errors"
	"math"
	"sort"
)

type matchStat struct {
	first uint64
	count uint64
	found bool
}

type automatonNode struct {
	next map[byte]int
	fail int
	out  []int
}

type automaton struct {
	nodes    []automatonNode
	patterns [][]byte
}

func newAutomaton(patterns [][]byte) *automaton {
	a := &automaton{nodes: []automatonNode{{next: make(map[byte]int)}}, patterns: patterns}
	for index, pattern := range patterns {
		state := 0
		for _, value := range pattern {
			next, ok := a.nodes[state].next[value]
			if !ok {
				next = len(a.nodes)
				a.nodes[state].next[value] = next
				a.nodes = append(a.nodes, automatonNode{next: make(map[byte]int)})
			}
			state = next
		}
		a.nodes[state].out = append(a.nodes[state].out, index)
	}
	a.buildFailures()
	return a
}

func (a *automaton) buildFailures() {
	queue := make([]int, 0, len(a.nodes))
	for _, value := range sortedTransitions(a.nodes[0].next) {
		state := a.nodes[0].next[value]
		a.nodes[state].fail = 0
		queue = append(queue, state)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for _, value := range sortedTransitions(a.nodes[state].next) {
			next := a.nodes[state].next[value]
			failure := a.nodes[state].fail
			for failure != 0 {
				if candidate, ok := a.nodes[failure].next[value]; ok {
					failure = candidate
					break
				}
				failure = a.nodes[failure].fail
			}
			if failure == 0 {
				if candidate, ok := a.nodes[0].next[value]; ok && candidate != next {
					failure = candidate
				}
			}
			a.nodes[next].fail = failure
			a.nodes[next].out = append(a.nodes[next].out, a.nodes[failure].out...)
			sort.Ints(a.nodes[next].out)
			queue = append(queue, next)
		}
	}
}

func sortedTransitions(values map[byte]int) []byte {
	keys := make([]byte, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

type streamMatcher struct {
	ctx       context.Context
	automaton *automaton
	state     int
	offset    uint64
	limit     int64
	stats     []matchStat
}

func (a *automaton) stream(ctx context.Context, limit int64) *streamMatcher {
	return &streamMatcher{ctx: ctx, automaton: a, limit: limit, stats: make([]matchStat, len(a.patterns))}
}

func (m *streamMatcher) Write(value []byte) (int, error) {
	if err := m.ctx.Err(); err != nil {
		return 0, err
	}
	if m.limit >= 0 && int64(len(value)) > m.limit-int64(m.offset) {
		return 0, errByteLimit
	}
	for index, current := range value {
		for m.state != 0 {
			if _, ok := m.automaton.nodes[m.state].next[current]; ok {
				break
			}
			m.state = m.automaton.nodes[m.state].fail
		}
		if next, ok := m.automaton.nodes[m.state].next[current]; ok {
			m.state = next
		}
		absoluteEnd := m.offset + uint64(index) + 1
		for _, patternIndex := range m.automaton.nodes[m.state].out {
			stat := &m.stats[patternIndex]
			if !stat.found {
				stat.found = true
				stat.first = absoluteEnd - uint64(len(m.automaton.patterns[patternIndex]))
			}
			if stat.count != math.MaxUint64 {
				stat.count++
			}
		}
	}
	m.offset += uint64(len(value))
	return len(value), nil
}

var errByteLimit = errors.New("literal matching byte limit exceeded")
