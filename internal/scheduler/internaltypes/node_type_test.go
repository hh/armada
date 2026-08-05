package internaltypes

import (
	"fmt"
	"strings"
	"testing"

	"github.com/segmentio/fasthash/fnv1a"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	v1 "k8s.io/api/core/v1"
)

func TestNodeType_GetId(t *testing.T) {
	nodeType := makeSut()

	assert.True(t, nodeType.GetId() != 0)
}

func TestNodeType_GetTaints(t *testing.T) {
	nodeType := makeSut()

	assert.Equal(t,
		[]v1.Taint{
			{Key: "taint1", Value: "value1", Effect: v1.TaintEffectNoSchedule},
			{Key: "taint2", Value: "value2", Effect: v1.TaintEffectNoSchedule},
		},
		nodeType.GetTaints(),
	)
}

func TestNodeType_FindMatchingUntoleratedTaint(t *testing.T) {
	nodeType := makeSut()
	taint, ok := nodeType.FindMatchingUntoleratedTaint([]v1.Toleration{{Key: "taint1", Operator: v1.TolerationOpExists, Effect: v1.TaintEffectNoSchedule}})

	assert.True(t, ok)
	assert.Equal(t,
		v1.Taint{Key: "taint2", Value: "value2", Effect: v1.TaintEffectNoSchedule},
		taint)
}

func TestNodeTypeLabels(t *testing.T) {
	nodeType := makeSut()

	assert.Equal(t,
		map[string]string{
			"label1": "value1",
			"label2": "value2",
		},
		nodeType.GetLabels(),
	)

	val1, ok1 := nodeType.GetLabelValue("label1")
	assert.Equal(t, val1, "value1")
	assert.True(t, ok1)

	val2, ok2 := nodeType.GetLabelValue("not-there")
	assert.Equal(t, val2, "")
	assert.False(t, ok2)

	assert.Equal(t,
		map[string]string{
			"label3": "",
		},
		nodeType.GetUnsetIndexedLabels(),
	)

	val3, ok3 := nodeType.GetUnsetIndexedLabelValue("label3")
	assert.Equal(t, val3, "")
	assert.True(t, ok3)

	val4, ok4 := nodeType.GetUnsetIndexedLabelValue("not-there")
	assert.Equal(t, val4, "")
	assert.False(t, ok4)
}

// unsetLabel marks a label as absent from a node rather than set to a value.
// It contains characters that are not valid in a Kubernetes label value, so it
// can never be confused with a real value; see
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
const unsetLabel = "<unset>"

// Realistic taints, taken from the well-known Kubernetes set plus a couple of
// Armada-specific ones. The corpus deliberately includes taints that differ
// from each other in exactly one field, so that a taint field dropped from the
// hash shows up as a collision:
//   - node.kubernetes.io/not-ready appears with two effects, which is how the
//     kubelet actually applies it;
//   - dedicated appears with two values and with two effects.
var collisionTestTaints = []v1.Taint{
	{Key: "node.kubernetes.io/not-ready", Value: "", Effect: v1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/not-ready", Value: "", Effect: v1.TaintEffectNoExecute},
	{Key: "node.kubernetes.io/unreachable", Value: "", Effect: v1.TaintEffectNoExecute},
	{Key: "node.kubernetes.io/memory-pressure", Value: "", Effect: v1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/disk-pressure", Value: "", Effect: v1.TaintEffectNoSchedule},
	{Key: "nvidia.com/gpu", Value: "present", Effect: v1.TaintEffectNoSchedule},
	{Key: "dedicated", Value: "batch", Effect: v1.TaintEffectNoSchedule},
	{Key: "dedicated", Value: "analytics", Effect: v1.TaintEffectNoSchedule},
	{Key: "dedicated", Value: "batch", Effect: v1.TaintEffectPreferNoSchedule},
}

// Realistic indexed labels. An unsetLabel value means the label is absent from
// the node, which exercises the unsetIndexedLabels part of the id. The empty
// value for armadaproject.io/pool is a real, legal label value and must not be
// confused with the label being unset.
var collisionTestLabels = []struct {
	key    string
	values []string
}{
	{key: "kubernetes.io/arch", values: []string{"amd64", "arm64"}},
	{key: "kubernetes.io/os", values: []string{"linux", "windows"}},
	{key: "topology.kubernetes.io/zone", values: []string{"us-east-1a", "us-east-1b", unsetLabel}},
	{key: "node.kubernetes.io/instance-type", values: []string{"m5.large", "g4dn.xlarge", unsetLabel}},
	{key: "armadaproject.io/pool", values: []string{"cpu", "gpu", "", unsetLabel}},
}

// TestNodeTypeIdHasNoCollisions generates every combination of the realistic
// taints and labels above and asserts that no two distinct combinations share a
// node type id. Collisions do not break correctness, but they group unrelated
// node types together and so cost scheduling efficiency.
func TestNodeTypeIdHasNoCollisions(t *testing.T) {
	indexedTaints := map[string]bool{}
	for _, taint := range collisionTestTaints {
		indexedTaints[taint.Key] = true
	}
	indexedLabels := map[string]bool{}
	for _, label := range collisionTestLabels {
		indexedLabels[label.key] = true
	}

	labelCombinations := 1
	for _, label := range collisionTestLabels {
		labelCombinations *= len(label.values)
	}
	taintCombinations := 1 << len(collisionTestTaints)
	totalCombinations := taintCombinations * labelCombinations
	require.Greater(t, totalCombinations, 1000, "the test should cover at least a thousand combinations")

	idToDescription := make(map[uint64]string, totalCombinations)
	for taintMask := 0; taintMask < taintCombinations; taintMask++ {
		taints := make([]v1.Taint, 0, len(collisionTestTaints))
		for i, taint := range collisionTestTaints {
			if taintMask&(1<<i) != 0 {
				taints = append(taints, taint)
			}
		}
		for labelMask := 0; labelMask < labelCombinations; labelMask++ {
			labels := make(map[string]string, len(collisionTestLabels))
			remainder := labelMask
			for _, label := range collisionTestLabels {
				value := label.values[remainder%len(label.values)]
				remainder /= len(label.values)
				if value != unsetLabel {
					labels[label.key] = value
				}
			}

			id := NewNodeType(taints, labels, indexedTaints, indexedLabels).GetId()
			description := describeNodeType(taints, labels)
			if colliding, ok := idToDescription[id]; ok {
				require.Failf(t, "node type id collision",
					"id %d is shared by two distinct node types:\n  %s\n  %s", id, colliding, description)
			}
			idToDescription[id] = description
		}
	}
	assert.Len(t, idToDescription, totalCombinations)
}

// TestNodeTypeIdHashInputIsNeverEmpty covers the second half of the original
// TODO. nodeTypeIdFromTaintsAndLabels hashes incrementally rather than building
// an intermediate string, so "the string is never empty" means "at least one
// byte is always fed into the hash", i.e. the id is never the bare FNV-1a
// offset basis. The two group separators guarantee this even for a node type
// with no taints and no labels at all.
func TestNodeTypeIdHashInputIsNeverEmpty(t *testing.T) {
	tests := map[string]*NodeType{
		"nil everything": NewNodeType(nil, nil, nil, nil),
		"empty everything": NewNodeType(
			[]v1.Taint{}, map[string]string{}, map[string]bool{}, map[string]bool{}),
		"taints only": NewNodeType(
			[]v1.Taint{{Key: "dedicated", Value: "batch", Effect: v1.TaintEffectNoSchedule}},
			nil, map[string]bool{"dedicated": true}, nil),
		"labels only": NewNodeType(
			nil, map[string]string{"kubernetes.io/arch": "amd64"},
			nil, map[string]bool{"kubernetes.io/arch": true}),
		"unset indexed labels only": NewNodeType(
			nil, nil, nil, map[string]bool{"kubernetes.io/arch": true}),
	}
	for name, nodeType := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NotEqual(t, uint64(fnv1a.Init64), nodeType.GetId())
			assert.NotZero(t, nodeType.GetId())
		})
	}
}

// TestNodeTypeIdIsIndependentOfInputOrder covers the reason NewNodeType sorts:
// the same node must produce the same id however its taints and labels happen
// to be ordered.
//
// This holds for taints with distinct keys. Taints are sorted by key alone (see
// the "TODO: Use less ambiguous sorting" in node_type.go), so two taints that
// share a key are left in whatever order they arrived in and do change the id.
// That is a separate, pre-existing issue and is deliberately not asserted here.
func TestNodeTypeIdIsIndependentOfInputOrder(t *testing.T) {
	indexedTaints := map[string]bool{"dedicated": true, "nvidia.com/gpu": true}
	indexedLabels := map[string]bool{"kubernetes.io/arch": true, "kubernetes.io/os": true, "topology.kubernetes.io/zone": true}
	labels := map[string]string{"kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux"}

	forwards := NewNodeType([]v1.Taint{
		{Key: "dedicated", Value: "batch", Effect: v1.TaintEffectNoSchedule},
		{Key: "nvidia.com/gpu", Value: "present", Effect: v1.TaintEffectNoSchedule},
	}, labels, indexedTaints, indexedLabels)
	backwards := NewNodeType([]v1.Taint{
		{Key: "nvidia.com/gpu", Value: "present", Effect: v1.TaintEffectNoSchedule},
		{Key: "dedicated", Value: "batch", Effect: v1.TaintEffectNoSchedule},
	}, labels, indexedTaints, indexedLabels)

	assert.Equal(t, forwards.GetId(), backwards.GetId())
}

// TestNodeTypeIdDistinguishesSetAndUnsetLabels checks the separator scheme
// itself: a label set to the empty string and a label that is not set at all
// are different node types, and must not hash to the same id.
func TestNodeTypeIdDistinguishesSetAndUnsetLabels(t *testing.T) {
	indexedLabels := map[string]bool{"armadaproject.io/pool": true}

	setToEmpty := NewNodeType(nil, map[string]string{"armadaproject.io/pool": ""}, nil, indexedLabels)
	notSet := NewNodeType(nil, nil, nil, indexedLabels)

	require.Empty(t, notSet.GetLabels())
	assert.NotEqual(t, setToEmpty.GetId(), notSet.GetId())
}

// TestNodeTypeIdIncludesUnsetIndexedLabels checks that the unset indexed labels
// contribute to the id in their own right. Two nodes carrying identical labels
// are different node types if different labels are indexed, because they are
// selectable by different pod label requirements.
func TestNodeTypeIdIncludesUnsetIndexedLabels(t *testing.T) {
	labels := map[string]string{"kubernetes.io/arch": "amd64"}

	zoneIndexed := NewNodeType(nil, labels, nil,
		map[string]bool{"kubernetes.io/arch": true, "topology.kubernetes.io/zone": true})
	instanceTypeIndexed := NewNodeType(nil, labels, nil,
		map[string]bool{"kubernetes.io/arch": true, "node.kubernetes.io/instance-type": true})

	require.Equal(t, zoneIndexed.GetLabels(), instanceTypeIndexed.GetLabels())
	require.NotEqual(t, zoneIndexed.GetUnsetIndexedLabels(), instanceTypeIndexed.GetUnsetIndexedLabels())
	assert.NotEqual(t, zoneIndexed.GetId(), instanceTypeIndexed.GetId())
}

// describeNodeType renders the inputs to NewNodeType as a string that is unique
// per distinct input, so that a collision can name both node types involved.
func describeNodeType(taints []v1.Taint, labels map[string]string) string {
	taintDescriptions := make([]string, 0, len(taints))
	for _, taint := range taints {
		taintDescriptions = append(taintDescriptions, fmt.Sprintf("%s=%s:%s", taint.Key, taint.Value, taint.Effect))
	}

	labelKeys := maps.Keys(labels)
	slices.Sort(labelKeys)
	labelDescriptions := make([]string, 0, len(labelKeys))
	for _, key := range labelKeys {
		labelDescriptions = append(labelDescriptions, fmt.Sprintf("%s=%q", key, labels[key]))
	}

	return fmt.Sprintf("taints[%s] labels[%s]",
		strings.Join(taintDescriptions, " "), strings.Join(labelDescriptions, " "))
}

func makeSut() *NodeType {
	taints := []v1.Taint{
		{Key: "taint1", Value: "value1", Effect: v1.TaintEffectNoSchedule},
		{Key: "not-indexed-taint", Value: "not-indexed-taint-value", Effect: v1.TaintEffectNoSchedule},
		{Key: "taint2", Value: "value2", Effect: v1.TaintEffectNoSchedule},
	}

	labels := map[string]string{
		"label1":             "value1",
		"label2":             "value2",
		"not-indexed-label;": "not-indexed-label-value",
	}

	return NewNodeType(
		taints,
		labels,
		map[string]bool{"taint1": true, "taint2": true, "taint3": true},
		map[string]bool{"label1": true, "label2": true, "label3": true},
	)
}
