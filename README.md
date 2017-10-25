# OSDFCon2017
OSDFCon 2017 Resources

## Tools Used
| Artifact | Tool | Output Type | Link |
| --- | --- | --- | --- |
| | ArangoDB | | https://www.arangodb.com/ |
| Shellbags | ShellBagsExplorer | CSV Output | https://ericzimmerman.github.io/ |
| Link Files | GcLinkParser* | JSON Output | https://github.com/devgc/GcLinkParser |
| Event Logs | events2jsonl | JSONL Output | https://github.com/devgc/events2jsonl |
| MFT | RustyMft | JSONL Output | https://github.com/forensicmatt/RustyMft |
| Prefetch | RustyPrefetch | JSONL Output | https://github.com/forensicmatt/RustyPrefetch |
| USN | RustyUsn | JSONL Output | https://github.com/forensicmatt/RustyUsn |

**\*** Output from GcLinkParser had to be broken down to JSONL format.

## Ingesting Data
For ingesting data, ArangoDB ships with a tool called Arangoimp: https://docs.arangodb.com/3.2/Manual/Administration/Arangoimp.html#arangoimp.

**\*** If you use Powershell to run tools the output will be in UTF16 and must be converted to an encoding that can be read by Arangoimp (I used UTF8).

#### Example
```
C:\ArangoDB3-3.2.2-1_win64_osdfcon\ArangoDB3-3.2.2-1_win64\usr\bin>
.\arangoimp.exe --collection mft --create-collection true --server.database test_database --file
 E:\TestData\mft.jsonl
Please specify a password:
Connected to ArangoDB 'http+tcp://127.0.0.1:8529', version 3.2.2, database: 'test_database', username: 'root'
----------------------------------------
database:               test_database
collection:             mft
create:                 yes
source filename:        E:\TestData\mft.jsonl
file type:              json
threads:                2
connect timeout:        5
request timeout:        1200
----------------------------------------
Starting JSON import...
2017-10-24T14:11:57Z [2368] INFO processed 20217239 bytes (3%) of input file
2017-10-24T14:11:57Z [2368] INFO processed 40434478 bytes (6%) of input file
2017-10-24T14:11:58Z [2368] INFO processed 60651717 bytes (9%) of input file
2017-10-24T14:11:58Z [2368] INFO processed 80836189 bytes (12%) of input file
2017-10-24T14:11:59Z [2368] INFO processed 101053428 bytes (15%) of input file
2017-10-24T14:11:59Z [2368] INFO processed 121270667 bytes (18%) of input file
2017-10-24T14:11:59Z [2368] INFO processed 141455139 bytes (21%) of input file
2017-10-24T14:12:00Z [2368] INFO processed 161672378 bytes (24%) of input file
2017-10-24T14:12:00Z [2368] INFO processed 181889617 bytes (27%) of input file
2017-10-24T14:12:01Z [2368] INFO processed 202106856 bytes (30%) of input file
2017-10-24T14:12:01Z [2368] INFO processed 222291328 bytes (33%) of input file
2017-10-24T14:12:02Z [2368] INFO processed 242508567 bytes (36%) of input file
2017-10-24T14:12:02Z [2368] INFO processed 262725806 bytes (39%) of input file
2017-10-24T14:12:02Z [2368] INFO processed 282910278 bytes (42%) of input file
2017-10-24T14:12:03Z [2368] INFO processed 303127517 bytes (45%) of input file
2017-10-24T14:12:03Z [2368] INFO processed 323344756 bytes (48%) of input file
2017-10-24T14:12:04Z [2368] INFO processed 343561995 bytes (51%) of input file
2017-10-24T14:12:04Z [2368] INFO processed 363746467 bytes (54%) of input file
2017-10-24T14:12:04Z [2368] INFO processed 383963706 bytes (57%) of input file
2017-10-24T14:12:05Z [2368] INFO processed 404180945 bytes (60%) of input file
2017-10-24T14:12:05Z [2368] INFO processed 424365417 bytes (63%) of input file
2017-10-24T14:12:06Z [2368] INFO processed 444582656 bytes (66%) of input file
2017-10-24T14:12:06Z [2368] INFO processed 464799895 bytes (69%) of input file
2017-10-24T14:12:06Z [2368] INFO processed 485017134 bytes (72%) of input file
2017-10-24T14:12:07Z [2368] INFO processed 505201606 bytes (75%) of input file
2017-10-24T14:12:07Z [2368] INFO processed 525418845 bytes (78%) of input file
2017-10-24T14:12:08Z [2368] INFO processed 545636084 bytes (81%) of input file
2017-10-24T14:12:08Z [2368] INFO processed 565820556 bytes (84%) of input file
2017-10-24T14:12:08Z [2368] INFO processed 586037795 bytes (87%) of input file
2017-10-24T14:12:09Z [2368] INFO processed 606255034 bytes (90%) of input file
2017-10-24T14:12:09Z [2368] INFO processed 626439506 bytes (93%) of input file
2017-10-24T14:12:10Z [2368] INFO processed 646656745 bytes (96%) of input file
2017-10-24T14:12:10Z [2368] INFO processed 666873984 bytes (99%) of input file

created:          293499
warnings/errors:  0
updated/replaced: 0
ignored:          0
```

## Queries Used
### Linkfile & Shellbag Corellation
```
FOR lnk IN lnks
    FILTER lnk.LnkTrgData.FileEntries != null
    FILTER lnk.DriveType == "DRIVE_REMOVABLE;"
    FOR entry IN lnk.LnkTrgData.FileEntries
        FOR extention IN entry.ExtentionBlocks
            FILTER extention.LongName != null
            FOR shellbag IN sbags
                FILTER (shellbag.Value == extention.LongName && 
                TO_NUMBER(shellbag.MFTEntry) == extention.EntryNum && 
                TO_NUMBER(shellbag.MFTSequenceNumber) == extention.SeqNum)
                RETURN DISTINCT {
                    "lnk.VolumeLabel": lnk.VolumeLabel,
                    "lnk.DriveSerialNumber": lnk.DriveSerialNumber,
                    "shellbag.AbsolutePath": shellbag.AbsolutePath,
                    "extention.LongName": extention.LongName, 
                    "extention.RefNum": extention.RefNum
                }
```
![Result](https://github.com/devgc/OSDFCon2017/blob/master/001_lnk_shl_result.png)

### Executables No Longer on System
```
// Get current exe on system
LET name_list = (
    FOR entry IN mft
        FILTER HAS(entry.attributes,'0x0030')
        FOR filename_attribute IN entry.attributes.`0x0030`
            FILTER LOWER(filename_attribute.content.name) LIKE "%.exe"
            RETURN UPPER(filename_attribute.content.name)
)

// Look for executables that ran that are no longer on the system
LET pf_exe_not_on_disk = (
    FOR pf IN prefetch
        FILTER NOT CONTAINS(name_list,pf.header.filename)
        RETURN pf.header.filename
)
    
//Get usn exe filenames not on the system
LET usn_exe_not_on_disk = (
    FOR entry IN usn
        FILTER UPPER(entry.file_name) LIKE '%.EXE'
        FILTER NOT CONTAINS(name_list,entry.file_name)
        RETURN DISTINCT entry.file_name
)

LET unique_exes_not_on_disk = (
    UNIQUE(
        UNION(
            pf_exe_not_on_disk,
            usn_exe_not_on_disk
        )
    )
)

FOR exe IN unique_exes_not_on_disk
    RETURN {"filename":exe}
```
![Result](https://github.com/devgc/OSDFCon2017/blob/master/002_exe_not_on_system_result.png)

### IPs in Event Logs
```
LET ips = ['70.192.219.217','70.192.225.40','70.192.226.172','46.163.111.92']

FOR ip IN ips
    FOR event IN events
        // We need to make both the same CASE to insure contains match
        FILTER CONTAINS(event.UserData,ip)
        // Sort by event time
        SORT event.System.TimeCreated.SystemTime
        RETURN {
            "time":DATE_FORMAT(event.System.TimeCreated.SystemTime,'%mm/%dd/%yyyy %hh:%ii:%ss.%fff'),
            "provider":event.System.Provider.Name,
            "event_id": event.System.EventID,
            "record_id": event.System.EventRecordID,
            "event":event
        }
```
![Result](https://github.com/devgc/OSDFCon2017/blob/master/003_ip_search_result.png)
