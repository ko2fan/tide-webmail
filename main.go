package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/google/uuid"
)

type Session struct {
	Server   string
	Username string
	Password string
}

var sessions = struct {
	sync.RWMutex
	m map[string]Session
}{m: make(map[string]Session)}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server   string `json:"server"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	now := time.Now().Format("01/Jan/1970:12:00:00 +0000")

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("%s %d %s %s", now, http.StatusBadRequest, r.URL.Path, "LoginHandler: Invalid JSON payload")
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	imapClient, err := client.DialTLS(req.Server, nil)
	if err != nil {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "LoginHandler: Failed to connect to server")
		http.Error(w, "Could not connect to IMAP server", http.StatusInternalServerError)
		return
	}
	defer imapClient.Logout()

	if err := imapClient.Login(req.Username, req.Password); err != nil {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "LoginHandler: Failed to login")
		http.Error(w, "IMAP login failed", http.StatusUnauthorized)
		return
	}

	token := uuid.New().String()

	sessions.Lock()
	sessions.m[token] = Session{
		Server:   req.Server,
		Username: req.Username,
		Password: req.Password,
	}
	sessions.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
	log.Printf("%s %d %s %s", now, 200, r.URL.Path, "User logged in")
}

func foldersHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Format("01/Jan/1970:12:00:00 +0000")

	token := r.Header.Get("X-Session-Token")
	if token == "" {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "FoldersHandler: Missing token")
		http.Error(w, "Missing session token", http.StatusUnauthorized)
		return
	}

	sessions.RLock()
	sess, exists := sessions.m[token]
	sessions.RUnlock()
	if !exists {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "FoldersHandler: Invalid token")
		http.Error(w, "Invalid session token", http.StatusUnauthorized)
		return
	}

	imapClient, err := client.DialTLS(sess.Server, nil)
	if err != nil {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "FoldersHandler: Failed to connect to server")
		http.Error(w, "Could not connect to IMAP server", http.StatusInternalServerError)
		return
	}
	defer imapClient.Logout()

	if err := imapClient.Login(sess.Username, sess.Password); err != nil {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "FoldersHandler: Failed to login")
		http.Error(w, "IMAP login failed", http.StatusUnauthorized)
		return
	}

	mailboxes := make(chan *imap.MailboxInfo, 10)
	done := make(chan error, 1)
	go func() {
		done <- imapClient.List("", "*", mailboxes)
	}()

	var folders []string
	for m := range mailboxes {
		folders = append(folders, m.Name)
	}
	if err := <-done; err != nil {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "FoldersHandler: Failed to list folders")
		http.Error(w, "Error listing folders", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"folders": folders})

	log.Printf("%s %d %s %s", now, 200, r.URL.Path, "FoldersHandler: Folders retrieved")
}

func emailsHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Format("01/Jan/1970:12:00:00 +0000")

	token := r.Header.Get("X-Session-Token")
	if token == "" {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "EmailsHandler: Missing token")
		http.Error(w, "Missing session token", http.StatusUnauthorized)
		return
	}

	sessions.RLock()
	sess, exists := sessions.m[token]
	sessions.RUnlock()
	if !exists {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "EmailsHandler: Invalid token")
		http.Error(w, "Invalid session token", http.StatusUnauthorized)
		return
	}

	folder := r.URL.Query().Get("folder")
	if folder == "" {
		log.Printf("%s %d %s %s", now, http.StatusBadRequest, r.URL.Path, "EmailsHandler: Missing folder")
		http.Error(w, "Missing folder parameter", http.StatusBadRequest)
		return
	}

	imapClient, err := client.DialTLS(sess.Server, nil)
	if err != nil {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "EmailsHandler: Failed to connect to server")
		http.Error(w, "Could not connect to IMAP server", http.StatusInternalServerError)
		return
	}
	defer imapClient.Logout()

	if err := imapClient.Login(sess.Username, sess.Password); err != nil {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "EmailsHandler: Failed to login")
		http.Error(w, "IMAP login failed", http.StatusUnauthorized)
		return
	}

	mbox, err := imapClient.Select(folder, false)
	if err != nil {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "EmailsHandler: Failed to select folder")
		http.Error(w, "Could not select folder", http.StatusInternalServerError)
		return
	}

	if mbox.Messages == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"emails": []interface{}{}})
		log.Printf("%s %d %s %s", now, 200, r.URL.Path, "EmailsHandler: No emails to retrieve")
		return
	}

	seqset := new(imap.SeqSet)
	seqset.AddRange(1, mbox.Messages)

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		done <- imapClient.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope}, messages)
	}()

	var emails []map[string]interface{}
	for msg := range messages {
		email := map[string]interface{}{
			"seq":     msg.SeqNum,
			"subject": msg.Envelope.Subject,
			"from":    msg.Envelope.From,
			"date":    msg.Envelope.Date,
		}
		emails = append(emails, email)
	}

	if err := <-done; err != nil {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "EmailsHandler: Failed to list folders")
		http.Error(w, "Error fetching emails", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"emails": emails})

	log.Printf("%s %d %s %s", now, 200, r.URL.Path, "EmailsHandler: Emails retrieved")
}

func emailContentHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Format("01/Jan/1970:12:00:00 +0000")

	token := r.Header.Get("X-Session-Token")
	if token == "" {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "EmailContentHandler: Missing token")
		http.Error(w, "Missing session token", http.StatusUnauthorized)
		return
	}

	sessions.RLock()
	sess, exists := sessions.m[token]
	sessions.RUnlock()
	if !exists {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "EmailContentHandler: Invalid token")
		http.Error(w, "Invalid session token", http.StatusUnauthorized)
		return
	}

	folder := r.URL.Query().Get("folder")
	seqStr := r.URL.Query().Get("seq")
	if folder == "" || seqStr == "" {
		log.Printf("%s %d %s %s", now, http.StatusBadRequest, r.URL.Path, "EmailContentHandler: Missing folder/seq")
		http.Error(w, "Missing folder or seq parameter", http.StatusBadRequest)
		return
	}
	seqNum, err := strconv.Atoi(seqStr)
	if err != nil {
		log.Printf("%s %d %s %s", now, http.StatusBadRequest, r.URL.Path, "EmailContentHandler: Invalid seq parameter")
		http.Error(w, "Invalid sequence number", http.StatusBadRequest)
		return
	}

	imapClient, err := client.DialTLS(sess.Server, nil)
	if err != nil {
		log.Printf("%s %d %s %s",
			now,
			http.StatusInternalServerError,
			r.URL.Path,
			"EmailContentHandler: Failed to connect to server",
		)
		http.Error(w, "Could not connect to IMAP server", http.StatusInternalServerError)
		return
	}
	defer imapClient.Logout()

	if err := imapClient.Login(sess.Username, sess.Password); err != nil {
		log.Printf("%s %d %s %s", now, http.StatusUnauthorized, r.URL.Path, "EmailContentHandler: Failed to login")
		http.Error(w, "IMAP login failed", http.StatusUnauthorized)
		return
	}

	mbox, err := imapClient.Select(folder, false)
	if err != nil {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "EmailContentHandler: Failed to select folder")
		http.Error(w, "Could not select folder", http.StatusInternalServerError)
		return
	}

	if uint32(seqNum) > mbox.Messages || seqNum < 1 {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "EmailContentHandler: Invalid seq number")
		http.Error(w, "Sequence number out of range", http.StatusBadRequest)
		return
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(uint32(seqNum))

	section := &imap.BodySectionName{}

	messages := make(chan *imap.Message, 1)
	done := make(chan error, 1)
	go func() {
		done <- imapClient.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope, section.FetchItem()}, messages)
	}()

	msg := <-messages
	if msg == nil {
		log.Printf("%s %d %s %s", now, http.StatusNotFound, r.URL.Path, "EmailContentHandler: Email not found")
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	body := msg.GetBody(section)
	if body == nil {
		log.Printf("%s %d %s %s", now, http.StatusInternalServerError, r.URL.Path, "EmailContentHandler: No message body")
		http.Error(w, "Server didn't return message body", http.StatusInternalServerError)
		return
	}

	rawContent, err := io.ReadAll(body)
	if err != nil {
		log.Printf("%s %d %s %s",
			now,
			http.StatusInternalServerError,
			r.URL.Path,
			"EmailContentHandler: Failed to read message body",
		)
		http.Error(w, "Error reading message body", http.StatusInternalServerError)
		return
	}

	plainText, htmlText, err := parseEmails(rawContent)
	if err != nil {
		log.Printf("%s %d %s %s",
			now,
			http.StatusInternalServerError,
			r.URL.Path,
			"EmailContentHandler: Failed to parse emails",
		)
		http.Error(w, "Error decoding email body: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"seq":     msg.SeqNum,
		"subject": msg.Envelope.Subject,
		"from":    msg.Envelope.From,
		"date":    msg.Envelope.Date,
		"plain":   plainText,
		"html":    htmlText,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("%s %d %s %s", now, 200, r.URL.Path, "EmailContentHandler: Email retrieved")
}

func parseEmails(rawContent []byte) (plainText string, htmlText string, err error) {
	msg, err := mail.ReadMessage(bytes.NewReader(rawContent))
	if err != nil {
		return "", "", err
	}

	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		body, err := io.ReadAll(msg.Body)
		if err != nil {
			return "", "", err
		}
		if strings.HasPrefix(ct, "text/html") {
			return "", string(body), nil
		}
		return string(body), "", nil
	}

	// Check for multipart messages.
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}
			pCt := part.Header.Get("Content-Type")
			pMediaType, _, err := mime.ParseMediaType(pCt)
			if err != nil {
				continue
			}
			partBody, err := io.ReadAll(part)
			if err != nil {
				continue
			}
			encoding := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))
			var decoded []byte
			switch encoding {
			case "base64":
				decoded, err = base64.StdEncoding.DecodeString(string(partBody))
				if err != nil {
					decoded = partBody // fallback
				}
			case "quoted-printable":
				qpReader := quotedprintable.NewReader(bytes.NewReader(partBody))
				decoded, err = io.ReadAll(qpReader)
				if err != nil {
					decoded = partBody
				}
			default:
				decoded = partBody
			}

			if pMediaType == "text/plain" && plainText == "" {
				plainText = string(decoded)
			} else if pMediaType == "text/html" && htmlText == "" {
				htmlText = string(decoded)
			}
		}
		return plainText, htmlText, nil
	}

	// For single-part messages.
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return "", "", err
	}
	encoding := strings.ToLower(msg.Header.Get("Content-Transfer-Encoding"))
	var decoded []byte
	switch encoding {
	case "base64":
		decoded, err = base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			decoded = body
		}
	case "quoted-printable":
		qpReader := quotedprintable.NewReader(bytes.NewReader(body))
		decoded, err = io.ReadAll(qpReader)
		if err != nil {
			decoded = body
		}
	default:
		decoded = body
	}
	if mediaType == "text/plain" {
		return string(decoded), "", nil
	} else if mediaType == "text/html" {
		return "", string(decoded), nil
	}
	return string(decoded), "", nil
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/folders", foldersHandler)
	http.HandleFunc("/emails", emailsHandler)
	http.HandleFunc("/email", emailContentHandler)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
