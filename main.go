package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"myapp/app/blockchain"
	"myapp/app/peer"
	"myapp/app/pkg/hmac"
	"myapp/app/pkg/signature"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	address := flag.String("address", "localhost:5000", "Address for node p2p network")
	init := flag.Bool("init", false, "init blockchain")
	flag.Parse()

	bootstrapAddress := "localhost:4000"
	// Membuat jaringan P2P dan kontrak voting.
	privateKey, err := signature.LoadOrCreateKeyPair("key.pem")
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}
	publicKey, err := signature.SerializePublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println("Error serializing public key:", err)
		return
	}
	println(string(publicKey))
	p2p := peer.NewP2PNetwork(bootstrapAddress, *address, privateKey, publicKey)
	peerConnect, err := p2p.RegisterToBootstrap()

	if err != nil || peerConnect == "" || peerConnect != "Your IP address is Registered" {
		if err == nil {
			fmt.Println("Failed to connect to bootstrap server:", peerConnect)
		} else {
			fmt.Println(err)
		}
		os.Exit(1)
	}

	fmt.Println("Connected to bootstrap server:", peerConnect)

	// Inisialisasi blockchain dengan instance Election
	p2p.Blockchain = &blockchain.Blockchain{
		Blocks:   []blockchain.Block{},
		Election: blockchain.NewElection([]string{}),
	}

	peers, err := p2p.GetPeersFromBootstrap()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, peer := range peers {
		fmt.Println("get peer from bootstrap", peer, peer.Address)
		if peer.Address != *address {
			p2p.AddPeer(peer)
			println("menambahkan: ", peer.Address)
		}
	}

	if *init {
		p2p.Blockchain.Election.AddCandidate("AndiBudi")
		p2p.Blockchain.Election.AddCandidate("CindyDinda")
		p2p.Blockchain.Election.AddCandidate("ErlingFawaz")
		println("prepare set genesis block")
		if !p2p.Blockchain.SetGenesisBlock() {
			p2p.BroadcastBlockchain()
		}
	} else {
		// Sinkronisasi blockchain untuk peer baru
		p2p.RequestBlockchainFromPeers()
	}

	// Mendengarkan koneksi untuk menerima blok.
	go p2p.ListenForBlocks(*address)

	// handling peer shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		p2p.NotifyBootstrapOnShutdown()
		os.Exit(0)
	}()

	// Daftarkan handler untuk setiap endpoint
	http.HandleFunc("/vote", func(w http.ResponseWriter, r *http.Request) {
		voteHandler(w, r, p2p)
	})
	http.HandleFunc("/showresult", func(w http.ResponseWriter, r *http.Request) {
		showResultHandler(w, r, p2p)
	})

	// Jalankan server
	fmt.Println("Server running on http://localhost:8082")

	go func() {
		http.ListenAndServe(":8082", nil)
	}()

	go handleUserInput(p2p)

	// Menjaga agar program tetap berjalan.
	select {}
}

func handleUserInput(p2p *peer.P2PNetwork) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Ketik perintah. Contoh: vote voterID kandidatID atau showresult")
	for scanner.Scan() {
		input := scanner.Text()
		args := strings.Fields(input)

		if len(args) == 0 {
			fmt.Println("Masukkan perintah yang valid.")
			continue
		}

		switch args[0] {
		case "vote":
			if len(args) < 3 {
				fmt.Println("Perintah vote harus diikuti oleh voterID dan kandidatID.")
				continue
			}
			voterID := args[1]
			candidateID := args[2]
			p2p.HandleVote(voterID, candidateID)
			fmt.Printf("Vote dari %s untuk %s telah dicatat.\n", voterID, candidateID)

		case "showresult":
			fmt.Println("Hasil voting saat ini:")
			p2p.Blockchain.Election.DisplayResults()
		case "display":
			fmt.Println("Blockchain saat ini:")
			p2p.Blockchain.Display()
		default:
			fmt.Println("Perintah tidak dikenal:", args[0])
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error membaca input:", err)
	}
}

// Struktur Election
type Election struct {
	Candidates map[string]int
	Voters     map[string]bool
	mu         sync.Mutex // Untuk melindungi akses ke data
}

// Fungsi untuk membuat instance Election baru
func NewElection(candidateList []string) *Election {
	candidates := make(map[string]int)
	for _, candidate := range candidateList {
		candidates[candidate] = 0
	}
	return &Election{
		Candidates: candidates,
		Voters:     make(map[string]bool),
	}
}

// Inisialisasi election instance
var election = NewElection([]string{"AndiBudi", "CindyDinda", "ErlingFawaz"})

// Fungsi untuk mencatat vote dan mengembalikan hasil sebagai string
func (e *Election) Vote(voterID string, candidateID string, p2p *peer.P2PNetwork) (string, string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Cek apakah kandidat valid
	if _, exists := e.Candidates[candidateID]; !exists {
		msg := fmt.Sprintf("Kandidat %s tidak valid", candidateID)
		fmt.Println(msg)
		return msg, "failed"
	}

	result, status := p2p.HandleVote(voterID, candidateID)
	return result, status
}

// Handler untuk endpoint /vote
func voteHandler(w http.ResponseWriter, r *http.Request, p2p *peer.P2PNetwork) {

	hmacSecret := r.Header.Get("X-HMAC")
	fmt.Println("HMAC Secret: ", hmacSecret)

	timeStampSecret := r.Header.Get("X-Timestamp")
	fmt.Println("Timestamp Secret: ", timeStampSecret)

	//ubah ke int64
	timeStampSecretInt, _ := strconv.ParseInt(timeStampSecret, 10, 64)

	// Verifikasi HMAC
	if hmacSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "failed",
			"error":  "HMAC Secret is required",
		})
		return
	}

	// Verifikasi HMAC
	hmac.VerifyHMAC(os.Getenv("HMAC_KEY_BLOCKCHAIN_ELECTION"), hmacSecret, timeStampSecretInt, 60)

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	//beri log
	fmt.Println("Vote request received")

	// Parse body request
	var req struct {
		VoterID     string `json:"voter_id"`
		CandidateID string `json:"candidate_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		})
		return
	}

	fmt.Printf("Vote request from %s for %s\n", req.VoterID, req.CandidateID)

	msg, status := election.Vote(req.VoterID, req.CandidateID, p2p)

	// Kirimkan respons dalam data JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"data":   msg,
		"time":   time.Now().Format(time.RFC3339),
	})
}

// Handler untuk endpoint /showresult
func showResultHandler(w http.ResponseWriter, r *http.Request, p2p *peer.P2PNetwork) {

	hmacSecret := r.Header.Get("X-HMAC")
	fmt.Println("HMAC Secret: ", hmacSecret)

	timeStampSecret := r.Header.Get("X-Timestamp")
	fmt.Println("Timestamp Secret: ", timeStampSecret)

	//ubah ke int64
	timeStampSecretInt, _ := strconv.ParseInt(timeStampSecret, 10, 64)

	// Verifikasi HMAC
	if hmacSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "failed",
			"error":  "HMAC Secret is required",
		})
		return
	}

	// Verifikasi HMAC
	hmac.VerifyHMAC(os.Getenv("HMAC_KEY_BLOCKCHAIN_ELECTION"), hmacSecret, timeStampSecretInt, 60)

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Ambil hasil voting
	results := p2p.Blockchain.Election.GetResults()

	// Encode hasil ke JSON dan kirimkan sebagai respons
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"results": results,
	})
}
