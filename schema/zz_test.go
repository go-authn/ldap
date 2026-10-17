package schema

import "testing"

func TestZZBuild(t *testing.T) {
	s, err := Build(StandardFiles()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(s.Syntaxes()), len(s.MatchingRules()), len(s.AttributeTypes()), len(s.ObjectClasses()), len(s.MatchingRuleUses()))
}
