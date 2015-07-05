package gokeepasslib

import (
	"encoding/xml"
	"time"
)

type DBContent struct {
	XMLName xml.Name  `xml:"KeePassFile"`
	Meta    *MetaData `xml:"Meta"`
	Root    *RootData `xml:"Root"`
}

type MetaData struct {
	Generator                  string        `xml:"Generator"`
	HeaderHash                 string        `xml:"HeaderHash"`
	DatabaseName               string        `xml:"DatabaseName"`
	DatabaseNameChanged        *time.Time    `xml:"DatabaseNameChanged"`
	DatabaseDescription        string        `xml:"DatabaseDescription"`
	DatabaseDescriptionChanged *time.Time    `xml:"DatabaseDescriptionChanged"`
	DefaultUserName            string        `xml:"DefaultUserName"`
	DefaultUserNameChanged     *time.Time    `xml:"DefaultUserNameChanged"`
	MaintenanceHistoryDays     string        `xml:"MaintenanceHistoryDays"`
	Color                      string        `xml:"Color"`
	MasterKeyChanged           *time.Time    `xml:"MasterKeyChanged"`
	MasterKeyChangeRec         int64         `xml:"MasterKeyChangeRec"`
	MasterKeyChangeForce       int64         `xml:"MasterKeyChangeForce"`
	MemoryProtection           MemProtection `xml:"MemoryProtection"`
	RecycleBinEnabled          bool          `xml:"RecycleBinEnabled"`
	RecycleBinUUID             string        `xml:"RecycleBinUUID"`
	RecycleBinChanged          *time.Time    `xml:"RecycleBinChanged"`
	EntryTemplatesGroup        string        `xml:"EntryTemplatesGroup"`
	EntryTemplatesGroupChanged *time.Time    `xml:"EntryTemplatesGroupChanged"`
	HistoryMaxItems            int64         `xml:"HistoryMaxItems"`
	HistoryMaxSize             int64         `xml:"HistoryMaxSize"`
	LastSelectedGroup          string        `xml:"LastSelectedGroup"`
	LastTopVisibleGroup        string        `xml:"LastTopVisibleGroup"`
	Binaries                   string        `xml:"Binaries"`
	CustomData                 string        `xml:"CustomData"`
}

type MemProtection struct {
	ProtectTitle    bool `xml:"ProtectTitle"`
	ProtectUserName bool `xml:"ProtectUserName"`
	ProtectPassword bool `xml:"ProtectPassword"`
	ProtectURL      bool `xml:"ProtectURL"`
	ProtectNotes    bool `xml:"ProtectNotes"`
}

type RootData struct {
	Groups         []Group             `xml:"Group"`
	DeletedObjects []DeletedObjectData `xml:"DeletedObjects>DeletedObject"`
}

type Group struct {
	UUID                    string   `xml:"UUID"`
	Name                    string   `xml:"Name"`
	Notes                   string   `xml:"Notes"`
	IconID                  int64    `xml:"IconID"`
	Times                   TimeData `xml:"Times"`
	IsExpanded              bool     `xml:"IsExpanded`
	DefaultAutoTypeSequence string   `xml:"DefaultAutoTypeSequence`
	EnableAutoType          string   `xml:"EnableAutoType`
	EnableSearching         string   `xml:"EnableSearching`
	LastTopVisibleEntry     string   `xml:"LastTopVisibleEntry`
	Groups                  []Group  `xml:"Group,omitempty"`
	Entries                 []Entry  `xml:"Entry,omitempty"`
}

type TimeData struct {
	CreationTime         *time.Time `xml:"CreationTime"`
	LastModificationTime *time.Time `xml:"LastModificationTime"`
	LastAcessTime        *time.Time `xml:"LastAcessTime"`
	ExpiryTime           *time.Time `xml:"ExpiryTime"`
	Expires              bool       `xml:"Expires"`
	UsageCount           int64      `xml:"UsageCount"`
	LocationChanged      *time.Time `xml:"LocationChanged"`
}

type Entry struct {
	UUID            string       `xml:"UUID"`
	IconID          int64        `xml:"IconID"`
	ForegroundColor string       `xml:"ForegroundColor"`
	BackgroundColor string       `xml:"BackgroundColor"`
	OverrideURL     string       `xml:"OverrideURL"`
	Tags            string       `xml:"Tags"`
	Times           TimeData     `xml:"Times"`
	Values          []ValueData  `xml:"String,omitempty"`
	AutoType        AutoTypeData `xml:"AutoType"`
	Histories       []History    `xml:"History`
	Password        []byte       `xml:"-"`
}

func (e *Entry) protected() bool {
	for _, v := range e.Values {
		if v.Key == "Password" && *v.Value.Protected {
			return true
		}
	}
	return false
}

func (e *Entry) getPassword() string {
	var val string
	for _, v := range e.Values {
		if v.Key == "Password" {
			val = v.Value.Content
		}
	}
	return val
}

func (e *Entry) getPasswordIndex() int {
	for i, v := range e.Values {
		if v.Key == "Password" {
			return i
		}
	}
	return 0
}

func (e *Entry) GetTitle() string {
	var val string
	for _, v := range e.Values {
		if v.Key == "Title" {
			val = v.Value.Content
		}
	}
	return val
}

type History struct {
	Entries []Entry `xml:"Entry"`
}

type ValueData struct {
	Key   string `xml:"Key"`
	Value V      `xml:"Value"`
}

type V struct {
	Content   string `xml:",innerxml"`
	Protected *bool  `xml:"Protected,attr,omitempty"`
}

type AutoTypeData struct {
	Enabled                 bool                `xml:"Enabled"`
	DataTransferObfuscation int64               `xml:"DataTransferObfuscation"`
	Association             AutoTypeAssociation `xml:"Association"`
}

type AutoTypeAssociation struct {
	Window            string `xml:"Window"`
	KeystrokeSequence string `xml:"KeystrokeSequence"`
}

type DeletedObjectData struct {
	XMLName      xml.Name   `xml:"DeletedObject"`
	UUID         string     `xml:"UUID"`
	DeletionTime *time.Time `xml:"DeletionTime"`
}
