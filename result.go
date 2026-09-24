// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "fmt"

// A ResultCode is the resultCode of an LDAPResult (RFC 4511 4.1.9, and the
// enumeration in Appendix B).
//
// It is a named type and not an int, because the difference between
// invalidCredentials and authMethodNotSupported is the difference between
// "try again" and "not this way", and a client acts on it. A field typed int
// lets any number through and reads the same at every call site.
type ResultCode uint16

// The result codes. The gaps are the specification's: 9, 15, 22-31, 35,
// 37-47, 55-63, 70 and 72-79 are reserved or unused, and are left out rather
// than filled in, so that a reader can see the enumeration IS the RFC's.
const (
	Success                      ResultCode = 0
	OperationsError              ResultCode = 1
	ProtocolError                ResultCode = 2
	TimeLimitExceeded            ResultCode = 3
	SizeLimitExceeded            ResultCode = 4
	CompareFalse                 ResultCode = 5
	CompareTrue                  ResultCode = 6
	AuthMethodNotSupported       ResultCode = 7
	StrongerAuthRequired         ResultCode = 8
	Referral                     ResultCode = 10
	AdminLimitExceeded           ResultCode = 11
	UnavailableCriticalExtension ResultCode = 12
	ConfidentialityRequired      ResultCode = 13
	SaslBindInProgress           ResultCode = 14
	NoSuchAttribute              ResultCode = 16
	UndefinedAttributeType       ResultCode = 17
	InappropriateMatching        ResultCode = 18
	ConstraintViolation          ResultCode = 19
	AttributeOrValueExists       ResultCode = 20
	InvalidAttributeSyntax       ResultCode = 21
	NoSuchObject                 ResultCode = 32
	AliasProblem                 ResultCode = 33
	InvalidDNSyntax              ResultCode = 34
	AliasDereferencingProblem    ResultCode = 36
	InappropriateAuthentication  ResultCode = 48
	InvalidCredentials           ResultCode = 49
	InsufficientAccessRights     ResultCode = 50
	Busy                         ResultCode = 51
	Unavailable                  ResultCode = 52
	UnwillingToPerform           ResultCode = 53
	LoopDetect                   ResultCode = 54
	NamingViolation              ResultCode = 64
	ObjectClassViolation         ResultCode = 65
	NotAllowedOnNonLeaf          ResultCode = 66
	NotAllowedOnRDN              ResultCode = 67
	EntryAlreadyExists           ResultCode = 68
	ObjectClassModsProhibited    ResultCode = 69
	AffectsMultipleDSAs          ResultCode = 71
	Other                        ResultCode = 80
)

var resultNames = map[ResultCode]string{
	Success: "success", OperationsError: "operationsError",
	ProtocolError: "protocolError", TimeLimitExceeded: "timeLimitExceeded",
	SizeLimitExceeded: "sizeLimitExceeded", CompareFalse: "compareFalse",
	CompareTrue: "compareTrue", AuthMethodNotSupported: "authMethodNotSupported",
	StrongerAuthRequired: "strongerAuthRequired", Referral: "referral",
	AdminLimitExceeded:           "adminLimitExceeded",
	UnavailableCriticalExtension: "unavailableCriticalExtension",
	ConfidentialityRequired:      "confidentialityRequired",
	SaslBindInProgress:           "saslBindInProgress",
	NoSuchAttribute:              "noSuchAttribute",
	UndefinedAttributeType:       "undefinedAttributeType",
	InappropriateMatching:        "inappropriateMatching",
	ConstraintViolation:          "constraintViolation",
	AttributeOrValueExists:       "attributeOrValueExists",
	InvalidAttributeSyntax:       "invalidAttributeSyntax",
	NoSuchObject:                 "noSuchObject", AliasProblem: "aliasProblem",
	InvalidDNSyntax:             "invalidDNSyntax",
	AliasDereferencingProblem:   "aliasDereferencingProblem",
	InappropriateAuthentication: "inappropriateAuthentication",
	InvalidCredentials:          "invalidCredentials",
	InsufficientAccessRights:    "insufficientAccessRights",
	Busy:                        "busy", Unavailable: "unavailable",
	UnwillingToPerform: "unwillingToPerform", LoopDetect: "loopDetect",
	NamingViolation: "namingViolation", ObjectClassViolation: "objectClassViolation",
	NotAllowedOnNonLeaf: "notAllowedOnNonLeaf", NotAllowedOnRDN: "notAllowedOnRDN",
	EntryAlreadyExists:        "entryAlreadyExists",
	ObjectClassModsProhibited: "objectClassModsProhibited",
	AffectsMultipleDSAs:       "affectsMultipleDSAs", Other: "other",
}

// String is the specification's own name for the code, which is what a log
// line and a client's error message should both say.
func (c ResultCode) String() string {
	if n, ok := resultNames[c]; ok {
		return n
	}
	return fmt.Sprintf("resultCode(%d)", uint16(c))
}

// OK reports whether this code means the operation succeeded.
//
// ⛔ compareTrue and compareFalse are both answers to a Compare and neither
// is a failure; saslBindInProgress is a bind that has not finished. A caller
// that tests `code == Success` treats all three as errors, which is why this
// exists rather than that comparison.
func (c ResultCode) OK() bool {
	switch c {
	case Success, CompareTrue, CompareFalse, SaslBindInProgress, Referral:
		return true
	}
	return false
}

// A Result is an LDAPResult: what every operation answers (RFC 4511 4.1.9).
//
// ⛔ MatchedDN and Diagnostic are fields here and not an afterthought,
// because they are fields of the protocol. A server that cannot set
// MatchedDN cannot tell a client how far along a DN the search base stopped
// existing -- which is the difference between "you have a typo in ou=" and
// "that whole tree is gone". The library this replaces hardcoded both to the
// empty string at every call site, so no server built on it could say either.
type Result struct {
	Code ResultCode
	// MatchedDN is the part of the requested DN that DOES exist. RFC 4511
	// 4.1.9 says it is set for noSuchObject, aliasProblem, invalidDNSyntax
	// and aliasDereferencingProblem, and is empty otherwise.
	MatchedDN string
	// Diagnostic is for a person reading a log, and MAY be empty. It is not a
	// machine-readable field and nothing should parse it.
	Diagnostic string
	// Referral is the URIs to ask instead, and is set only with the referral
	// code (RFC 4511 4.1.10).
	Referral []string
}

// Err makes an error of a result that is not a success, and nil of one that
// is.
func (r Result) Err() error {
	if r.Code.OK() {
		return nil
	}
	return &Error{Result: r}
}

// An Error is a result that refused.
type Error struct{ Result }

func (e *Error) Error() string {
	if e.Diagnostic == "" {
		return "ldap: " + e.Code.String()
	}
	return "ldap: " + e.Code.String() + ": " + e.Diagnostic
}

// Refuse is the short way to build a refusal with a reason.
func Refuse(code ResultCode, format string, args ...any) Result {
	return Result{Code: code, Diagnostic: fmt.Sprintf(format, args...)}
}
