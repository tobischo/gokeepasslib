package gokeepasslib

import (
	"encoding/xml"
	"time"
)

type Content struct {
	XMLName xml.Name `xml:"KeePassFile"`
	Meta    meta     `xml:"Meta"`
	Root    root     `xml:"Root"`
}

type meta struct {
	Generator                  string           `xml:"Generator"`
	HeaderHash                 string           `xml:"HeaderHash"`
	DatabaseName               string           `xml:"DatabaseName"`
	DatabaseNameChanged        *time.Time       `xml:"DatabaseNameChanged"`
	DatabaseDescription        string           `xml:"DatabaseDescription"`
	DatabaseDescriptionChanged *time.Time       `xml:"DatabaseDescriptionChanged"`
	DefaultUserName            string           `xml:"DefaultUserName"`
	MaintenanceHistoryDays     string           `xml:"MaintenanceHistoryDays"`
	Color                      string           `xml:"Color"`
	MasterKeyChanged           *time.Time       `xml:"MasterKeyChanged"`
	MasterKeyChangedRec        int64            `xml:"MasterKeyChangedRec"`
	MasterKeyChangedForce      int64            `xml:"MasterKeyChangedForce"`
	MemoryProtection           memoryProtection `xml:"MemoryProtection"`
	RecycleBinEnabled          bool             `xml:"RecycleBinEnabled"`
	RecycleBinUUID             string           `xml:"RecycleBinUUID"`
	RecycleBinChanged          *time.Time       `xml:"RecycleBinChanged"`
	EntryTemplatesGroup        string           `xml:"EntryTemplatesGroup"`
	EntryTemplatesGroupChanged *time.Time       `xml:"EntryTemplatesGroupChanged"`
	HistoryMaxItems            int64            `xml:"HistoryMaxItems"`
	HistoryMaxSize             int64            `xml:"HistoryMaxSize"`
	LastSelectedGroup          string           `xml:"LastSelectedGroup"`
	LastTopVisibleGroup        string           `xml:"LastTopVisibleGroup"`
	Binaries                   interface{}      `xml:"Binaries"`
	CustomData                 interface{}      `xml:"CustomData"`
}

type memoryProtection struct {
	ProtectTitle    bool `xml:"ProtectTitle"`
	ProtectUserName bool `xml:"ProtectUserName"`
	ProtectPassword bool `xml:"ProtectPassword"`
	ProtectURL      bool `xml:"ProtectURL"`
	ProtectNotes    bool `xml:"ProtectNotes"`
}

type root struct {
	Group          group           `xml:"Group"`
	DeletedObjects []deletedObject `xml:"DeletedObjects>DeletedObject"`
}

type group struct {
	UUID                    string      `xml:"UUID"`
	Name                    string      `xml:"Name"`
	Notes                   interface{} `xml:"Notes"`
	IconID                  int64       `xml:"IconID"`
	Times                   times       `xml:"Times"`
	IsExpanded              bool        `xml:"IsExpanded`
	DefaultAutoTypeSequence string      `xml:"DefaultAutoTypeSequence`
	EnableAutoType          string      `xml:"EnableAutoType`
	EnableSearching         string      `xml:"EnableSearching`
	LastTopVisibleEntry     string      `xml:"LastTopVisibleEntry`
	Groups                  []group     `xml:"Group,omitempty"`
	Entries                 []entry     `xml:"Entry,omitempty"`
}

type times struct {
	CreationTime         *time.Time `xml:"CreationTime"`
	LastModificationTime *time.Time `xml:"LastModificationTime"`
	LastAcessTime        *time.Time `xml:"LastAcessTime"`
	ExpiryTime           *time.Time `xml:"ExpiryTime"`
	Expires              bool       `xml:"Expires"`
	UsageCount           int64      `xml:"UsageCount"`
	LocationChanged      *time.Time `xml:"LocationChanged"`
}

type entry struct {
	UUID            string      `xml:"UUID"`
	IconID          int64       `xml:"IconID"`
	ForegroundColor interface{} `xml:"ForegroundColor"`
	BackgroundColor interface{} `xml:"BackgroundColor"`
	OverrideURL     interface{} `xml:"OverrideURL"`
	Tags            interface{} `xml:"Tags"`
	Times           times       `xml:"Times"`
	Values          []value     `xml:"String,omitempty"`
	AutoType        autoType    `xml:"AutoType"`
}

type value struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
	//Protected attribute - how?
}

type autoType struct {
	Enabled                 bool  `xml:"Enabled"`
	DataTransferObfuscation int64 `xml:"DataTransferObfuscation"`
}

type deletedObject struct {
	XMLName      xml.Name   `xml:"DeletedObject"`
	UUID         string     `xml:"UUID"`
	DeletionTime *time.Time `xml:"DeletionTime"`
}
