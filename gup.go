package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"runtime"
	"sort"
	//"strconv"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pubmatic/pub-adserver/go/gup/conf"
)

// constants
const (
	_               = iota
	OPTOUT          = "optout"
	OLDOPTOUT       = "pmoo"
	OPTEDOUT        = "true"
	VCODE           = "vcode"
	OPCODE          = "o"
	PIXELTYPE       = "type"
	PIXELID         = "code"
	TTL             = "ttl"
	REDIRECTURL     = "r"
	UIDMACRO        = "${PUBMATIC_UID}"
	UID             = "${UID}"
	KADUSERCOOKIE   = "KADUSERCOOKIE"
	PIXELLANECOOKIE = "pi"
	PIGGYBACKCOOKIE = "piggybackCookie"
	PUBRETARGET     = "PUBRETARGET"
	QUERY           = "select pixel_id, advertiser_id from advertiser_pixel"
	CHANBUF         = 10000
	PIGGYBACKPIXEL  = 1
	RETARGETPIXEL   = 2
	SET             = 1
	UNSET           = 2
)

type pixelInfo struct {
	// Set/Unset
	opCode int
	// Retargeting for AdFlex(non-RTB campaigns) / Piggyback for RTB
	pixelType int
	pixelID   int
	// ttl in minutes
	ttl int
}

type queryParams struct {
	pixInfo         []pixelInfo
	redirectURL     string
	piggybackCookie string
}

type generalParams struct {
	pubID     int
	pixelLane int
}

type statUnit struct {
	key     string
	value   int
	statKey string
	statVal int
}

var statsChan (chan *statUnit)

type pixelDSPMap map[int][]int

var (
	pdm      [2]pixelDSPMap
	mapIndex int32
)

/*
const (
        cacheRefreshPeriodSec = 60 * 1
        dbuser                = "kdbuser"
        dbpass                = "KdBuSeR12!"
)
*/

func checkError(err error) {
	if err != nil {
		log.Fatal("Fatal error:%s\n", err.Error())
	}
}

func updatePixelDSPMap(db *sql.DB) {
	var (
		dpID    int
		pixelID int
	)

	//log.Printf("Updating DSP Map\n")
	tmpMap := make(pixelDSPMap)
	rows, err := db.Query(QUERY)

	if err != nil {
		log.Printf("ERROR db query: %s failed with error = %s", QUERY, err.Error())
		return
	}

	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&pixelID, &dpID)
		if err != nil {
			log.Printf("ERROR rows.Scan failed with error = %s", err.Error())
			return
		}
		tmpMap[pixelID] = append(tmpMap[pixelID], dpID)
	}

	currentIndex := atomic.LoadInt32(&mapIndex)
	newIndex := (currentIndex + 1) % 2
	pdm[newIndex] = tmpMap
	atomic.StoreInt32(&mapIndex, newIndex)
}

func cacheFiller() {
	//log.Printf("DEBUG in cacheFiller")
	db, err := sql.Open("mysql", conf.Config.Global.DBUser+":"+conf.Config.Global.DBPass+"@tcp("+conf.Config.Global.DBHost+")/AdFlex")
	if err != nil {
		log.Fatalf("ERROR sql.Open failed for %s:%s:%s with error = %s", conf.Config.Global.DBUser, conf.Config.Global.DBPass, conf.Config.Global.DBHost, err.Error())
	}
	defer db.Close()
	updatePixelDSPMap(db)
	tck := time.Tick(time.Second * time.Duration(conf.Config.Global.DBRefreshPeriod))
	for {
		select {
		case <-tck:
			updatePixelDSPMap(db)
		}
	}
}

func getDSPIDsfromPixel(pixelID int) []int {
	currentIndex := atomic.LoadInt32(&mapIndex)
	return pdm[currentIndex][pixelID]
}

// CkyList is []*http.Cookie
type CkyList []*http.Cookie

// Len
func (v CkyList) Len() int {
	return len(v)
}

// Search is
func (v CkyList) Search(key string) int {
	var (
		left   = 0
		right  = len(v) - 1
		idx = -1
	)
	for left <= right {
		middle := (left + right) / 2
		if key < v[middle].Name {
			right = middle - 1
		} else if key > v[middle].Name {
			left = middle + 1
		} else {	
			idx = middle
			break
		}
	}
	return idx
}

// Less
func (v CkyList) Less(i, j int) bool {
	return v[i].Name < v[j].Name
}

// Swap
func (v CkyList) Swap(i, j int) {
	v[i], v[j] = v[j], v[i]
}
func parseCookies(r *http.Request) CkyList {
	cookies := r.Cookies()
	if len(cookies) <= 0 {
		return nil
	}

	res := CkyList(cookies)
	sort.Sort(res)
	return res
}

// If any of the vcodes is incorrect, this function returns nil, error
func parseQueryParams(u *url.URL) (*queryParams, error) {

	var (
		vcs []string
		qp  queryParams
		err error
		byt []byte
		n   int
		//pb     string
		r      string
		ok     bool
		pxInfo pixelInfo
	)

	v := u.Query()

	if vcs, ok = v[VCODE]; ok != true {
		return nil, fmt.Errorf("ERROR vcode is missing in %s", u.RawQuery)
	}
	// We have got the vcodes, lets decode them one by one
	for i := range vcs {
		if byt, err = base64.URLEncoding.DecodeString(vcs[i]); err != nil {
			return nil, err
		}
		// We got the byte[] of the decoded vcode, now parse it
		if n, err = fmt.Sscanf(string(byt), "o=%d&type=%d&code=%d&ttl=%d", &pxInfo.opCode, &pxInfo.pixelType, &pxInfo.pixelID, &pxInfo.ttl); err != nil || n != 4 {
			return nil, fmt.Errorf("ERROR unable to parse vcode in %s", string(byt))
		}
		qp.pixInfo = append(qp.pixInfo, pxInfo)
	}
	// Parse piggybackCookie
	qp.piggybackCookie = v.Get(PIGGYBACKCOOKIE)
	// Parse redirectURL
	if r = v.Get(REDIRECTURL); r != "" {
		if qp.redirectURL, err = url.QueryUnescape(r); err != nil {
			return nil, fmt.Errorf("ERROR unable to unescape %s", r)
		}
	}
	log.Printf("DEBUG QueryParams = %#v\n", qp)
	return &qp, nil
}

func getGeneralParams(cookies CkyList) (*generalParams) {
	var g generalParams
	const unknownID = 1

	pubID := unknownID
	pixelLane := unknownID
	if cookies != nil {
		if idx := cookies.Search(PIXELLANECOOKIE); idx != -1 {
			if retcnt, err := fmt.Sscanf(cookies[idx].Value, "%d:%d", &pubID, &pixelLane); retcnt != 2 || err != nil {
				log.Printf("ERROR parsing pi query: %s\n",err.Error())
			}
		}
	}
	g.pixelLane = pixelLane
	g.pubID = pubID

	return &g
}

// NOTE(kartik.mahajan) Pointer os struct passed instead of struct member(type string)redirectURL for efficiency(remove copy overhead of string). Is it really efficient?
/*
func handleRedirection(w http.ResponseWriter, qp *queryParams, uid string) {
        strings.Replace(qp.redirectURL, kadusercookie, uid, -1)
}
*/

func handler(w http.ResponseWriter, r *http.Request) {

	var (
		err error
		//oo              *http.Cookie
		qp *queryParams
		//gp              *generalParams
		//piggybackCookie *http.Cookie
		uid string
		cks []*http.Cookie
		g   *generalParams
		//pr              *http.Cookie
	)
	// indicates the presence of PUBRETARGET cookie
	var (
		flag = false
		// new value of pubretarget cookie
		//prc       string
		v map[int]int64
		//maxExpiry = 0
	)
	// log the request for debugging purposes
	//log.Printf("DEBUG gup.handler() called\n")
	//log.Printf("DEBUG http.Request = %+v\n", r)
	//log.Printf("DEBUG http.Request = %#v\n", r)

	// Get the Cookies
	// TODO(@kartik.mahajan:- We should create a map of key values of cookies instead of splice OR atleast sort the splice before searching for a cookie
	cookies := parseCookies(r)
	//log.Printf("DEBUG cookies = %+v", cookies)
	//log.Printf("DEBUG cookies = %+v\n", cookies)

	// If no cookie found, this could be a browser where TPC(third-party-cookies) are disabled or the user just deleted all pubmatic cookies/New user

	// If opt out is set, DONE
	if cookies != nil {
		if idx := cookies.Search(OPTOUT); idx != -1 && cookies[idx].Value == OPTEDOUT {
			return
		}

		if idx := cookies.Search(OLDOPTOUT); idx != -1 && cookies[idx].Value == OPTEDOUT {
			return
		}

		if idx := cookies.Search(KADUSERCOOKIE); idx != -1 {
			uid = cookies[idx].Value
		}

	}
	g = getGeneralParams(cookies)

	// Parse the Query Parameters to get type, code, ttl, redirect url, piggybackCookie
	qp, err = parseQueryParams(r.URL)

	if err != nil {
		log.Printf("\nERROR parseQueryParams failed for %s, error = %s", r.URL.RawQuery, err.Error())
		return
	}

forloop:

	for i := range qp.pixInfo {

		pxInfo := qp.pixInfo[i]

		switch pxInfo.pixelType {

		case PIGGYBACKPIXEL:
			switch pxInfo.opCode {

			case SET:
				if qp.piggybackCookie != "" && qp.piggybackCookie != UID {
					cname := fmt.Sprintf("S_%d", pxInfo.pixelID)
					log.Printf("time = %+v\n", time.Now().UTC())
					expiration := time.Now().Add(time.Duration(pxInfo.ttl * 60) * time.Second).UTC()
					log.Printf("time = %+v\n", expiration)
					ck := &http.Cookie{Name: cname, Value: qp.piggybackCookie, Path: "/", Domain: ".pubmatic.com", Expires: expiration, HttpOnly: true}
					cks = append(cks, ck)
						log.Printf("Set Cookie List:%+v\n", cks)
				}

			case UNSET:
				cname := fmt.Sprintf("S_%d", pxInfo.pixelID)
				if idx := cookies.Search(cname); idx != -1 {
					expiration := time.Now().UTC()
					ck := &http.Cookie{Name: cname, Value: "", Path: "/", Domain: ".pubmatic.com", Expires: expiration, HttpOnly: true}
					cks = append(cks, ck)
				}

				default: 
					log.Fatal("ERROR: Invalid opcode:%d", pxInfo.opCode)
			}

			if conf.Config.Global.DeleteOldCookies == true {
				dsplist := getDSPIDsfromPixel(pxInfo.pixelID)
				//log.Printf("DSP List:%#v",dsplist)
				for j := range dsplist {
					cname := fmt.Sprintf("KRTBCOOKIE_%d", dsplist[j])
					if idx := cookies.Search(cname); idx != -1 {
						//log.Printf("Found old cookie for %d.. deleting..\n",dsplist[j])
						ck := &http.Cookie{Name: cname, Value: "", Path: "/", Domain: ".pubmatic.com", Expires: time.Now().UTC(), HttpOnly: true}
						cks = append(cks, ck)
					}
				}
					 log.Printf("Set Cookie List:%+v\n", cks)
			}

		case RETARGETPIXEL:
			if flag == false {
				if idx := cookies.Search(PUBRETARGET); idx != -1 {
					v, err = parseRC(cookies[idx])
					if err != nil {
						break forloop
					}
					flag = true
				}
			}

			switch pxInfo.opCode {

			case SET:
				v[pxInfo.pixelID] = int64(pxInfo.ttl) * 60

			case UNSET:
				if v != nil {
					delete(v, pxInfo.pixelID)
				}
			}
				
			default: 
				log.Fatal("ERROR: Invalid pixel type:%d", pxInfo.pixelType)
		}

		if conf.Config.Global.StatsEnabled == true {
			incrementPixelLaneStats(g.pixelLane, g.pubID, pxInfo.pixelID)
		}
	}

	if v != nil {
		ck := createCookie(v)
		cks = append(cks, ck)
	}

	for i := 0; i < len(cks); i++ {
log.Println("\nHI\n")
		http.SetCookie(w, cks[i])
	}

	// If redirect URL is present, replace the USER-ID with KRTBCOOKIE value DONE
	if qp.redirectURL != "" {
		if uid != "" {
			qp.redirectURL = strings.Replace(qp.redirectURL, UIDMACRO, uid, -1)
		}
		w.Header().Set("Location", qp.redirectURL)
		w.WriteHeader(http.StatusFound)
	}

	// Send data to pug logger
}

func createCookie(m map[int]int64) *http.Cookie {
	var (
		s         string
		maxExpire int64
	)
	for k, v := range m {
		s += fmt.Sprintf("%d_%d.", k, v)
		if maxExpire < v {
			maxExpire = v
		}
	}
	return &http.Cookie{Name: "PUBRETARGET", Value: s, Domain: ".pubmatic.com", Expires: time.Unix(maxExpire, 0), HttpOnly: true}
}

func parseRC(v *http.Cookie) (map[int]int64, error) {

	var (
		pID int
		ttl int64
	)

	k := strings.Split(v.Value, ".")

	if len(k) <= 0 {
		return nil, fmt.Errorf("ERROR incorrect format")
	}

	res := make(map[int]int64)
	for i := range k {
		if n, err := fmt.Sscanf(k[i], "%d_%d", &pID, ttl); n != 2 || err != nil {
			return nil, err
		}
		res[pID] = ttl
	}
	return res, nil
}

func main() {

	rand.Seed(time.Now().UTC().UnixNano())
	// Open the file to for the logs
	outputFile, err := os.Create(conf.Config.Global.ErrorFilePath)
	if err != nil {
		fmt.Printf("\nERROR os.Create() failed for %s with error : %s. Program Exiting.", conf.Config.Global.ErrorFilePath, err.Error())
		os.Exit(1)
	}

	// Set the logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(outputFile)

	// Use all the cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	if conf.Config.Global.DeleteOldCookies == true {
		go cacheFiller()
	}
	if conf.Config.Global.StatsEnabled == true {
		statsChan = make(chan *statUnit, CHANBUF)
		go statsHandler()
	}

	log.Printf("boot.conf.init.success:\nGOGC=%s\n\n***************Configuration:***************\n%+v\n*****************END****************\n", os.Getenv("GOGC"), conf.Config)

	// For profiling blocking
	//runtime.SetBlockProfileRate(1)
	http.HandleFunc("/g/gup", handler)
	//http.Handle("/", New(conf.Config.Global.Header, conf.Config.Global.QSizePerURL, conf.Config.Global.MaxConn, conf.Config.Global.MaxConnPerHost, conf.Config.Global.Chanbuff, time.Millisecond*time.Duration(conf.Config.Global.Timeout), time.Second*time.Duration(conf.Config.Global.LogFrequency)))

	// Sleep to ensure that the consumer go routine is spawned and waiting to serve requests
	time.Sleep(2 * time.Second)

	log.Printf("Starting the server on port %s", conf.Config.Global.Port)
	//log.Fatalln(s.ListenAndServe())
	log.Fatalln(http.ListenAndServe(conf.Config.Global.Port, nil))
}

/* Stat code*/
func initStats(server string, port int) (net.Conn, error) {
	con, err := net.Dial("udp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return con, nil
}

func addStats(con net.Conn, key string, count int) error {
	data := fmt.Sprintf("%d,%s\n", count, key)
	_, err := con.Write([]byte(data))
	if err != nil {
		log.Printf("STAT ERROR: data sending failed.. error:%s",err.Error())
		return err
	}
	//log.Printf("Data %s sent", data)
	return nil
}

func updateStats(s *statUnit) {
	statsChan <- s
}

func incrementEntityStats(entityID int, pixelLane int, entity string) {
	key := fmt.Sprintf("%s%d_%d", entity, entityID, pixelLane)
	statKey := fmt.Sprintf("PL:%s:%d:%d:%s", entity, entityID, pixelLane, conf.Config.Stats.DCName)
	s := statUnit{key: key, value: 1, statKey: statKey, statVal: conf.Config.Stats.StatsCounter}
	updateStats(&s)
}

func incrementPixelLaneStats(pixelLane int, pubID int, pixelID int) {
	incrementEntityStats(pubID, pixelLane, "pixel")
	incrementEntityStats(pixelID, pixelLane, "pub")
}

func statsHandler() {
	con, _ := initStats(conf.Config.Stats.Server, conf.Config.Stats.Port)
	statMap := make(map[string]int)
	for {
		select {
		case s := <-statsChan:
			val := statMap[s.key] + s.value
			if val >= s.statVal {
				_ = addStats(con, s.statKey, val)
				statMap[s.key] = 0
			} else {
				statMap[s.key] = val
			}
		} /*end of select*/
	} /*end of for*/
}
