package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Разрешаем любые запросы для упрощения
	},
}

type Player struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	X          float64   `json:"x"`
	Y          float64   `json:"y"`
	Direction  string    `json:"direction"`
	Moving     bool      `json:"moving"`
	Attacking  bool      `json:"attacking"`
	Hurt       bool      `json:"hurt"`
	Dead       bool      `json:"dead"`
	Health     int       `json:"health"`
	IP         string    `json:"ip"`
	IsAdmin    bool      `json:"is_admin"`
	Visible    bool      `json:"visible"`
	LastUpdate time.Time `json:"-"`
	LastAttack time.Time `json:"-"`
	LastHurt   time.Time `json:"-"`
}

type Mob struct {
	ID         string    `json:"id"`
	X          float64   `json:"x"`
	Y          float64   `json:"y"`
	Direction  string    `json:"direction"`
	Health     int       `json:"health"`
	LastUpdate time.Time `json:"-"`
}

type Projectile struct {
	ID         string    `json:"id"`
	X          float64   `json:"x"`
	Y          float64   `json:"y"`
	DX         float64   `json:"dx"`
	DY         float64   `json:"dy"`
	OwnerID    string    `json:"owner_id"`
	LastUpdate time.Time `json:"-"`
}

type GameState struct {
	Players     map[string]Player     `json:"Players"`
	Mobs        map[string]Mob        `json:"Mobs"`
	Projectiles map[string]Projectile `json:"Projectiles"`
	ServerTime  int64                 `json:"server_time"`
	ChatHistory []ChatMessage         `json:"chat_history"`
}

type ChatMessage struct {
	Sender  int    `json:"sender"`
	Message string `json:"message"`
}

type ClientMessage struct {
	Type   string `json:"type"`
	Left   bool   `json:"left,omitempty"`
	Right  bool   `json:"right,omitempty"`
	Up     bool   `json:"up,omitempty"`
	Down   bool   `json:"down,omitempty"`
	Attack bool   `json:"attack,omitempty"`
	Chat   string `json:"chat,omitempty"`
	Target string `json:"target,omitempty"`
	Token  string `json:"token,omitempty"`
}

type ServerMessage struct {
	Type        string                 `json:"type"`
	Status      string                 `json:"status,omitempty"`
	CID         string                 `json:"cid,omitempty"`
	Players     map[string]interface{} `json:"Players,omitempty"`
	Mobs        map[string]interface{} `json:"Mobs,omitempty"`
	Projectiles map[string]interface{} `json:"Projectiles,omitempty"`
	ServerTime  int64                  `json:"server_time,omitempty"`
	ChatHistory []ChatMessage          `json:"chat_history,omitempty"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

type UsersData struct {
	Banned     []string `json:"banned"`
	Admins     []string `json:"admins"`
	Registered []User   `json:"registered"`
}

var (
	players     = make(map[string]*Player)
	mobs        = make(map[string]*Mob)
	projectiles = make(map[string]*Projectile)
	connections = make(map[string]*websocket.Conn)
	chatHistory = []ChatMessage{}
	mutex       = sync.RWMutex{}
	nextMobID   = 0
	nextProjID  = 0
	startTime   = time.Now()
	usersData   UsersData
	jwtSecret   = []byte("your-secret-key") // Необходимо заменить на реальный секретный ключ!
)

const (
	WIDTH            = 1920
	HEIGHT           = 1080
	MAP_WIDTH        = 10000
	MAP_HEIGHT       = 10000
	PLAYER_SPEED     = 5
	MOB_SPEED        = 2
	PROJECTILE_SPEED = 10
)

func initMobs() {
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("mob_%d", nextMobID)
		nextMobID++
		mobs[id] = &Mob{
			ID:         id,
			X:          rand.Float64() * MAP_WIDTH,
			Y:          rand.Float64() * MAP_HEIGHT,
			Direction:  "down",
			Health:     100,
			LastUpdate: time.Now(),
		}
	}
}

func handleCommand(cid string, commandStr string, isAdmin bool) map[string]string {
	if !isAdmin {
		return map[string]string{"error": "Only admin can execute commands."}
	}

	parts := strings.Fields(strings.TrimSpace(commandStr))
	if len(parts) == 0 {
		return map[string]string{"error": "Invalid command syntax."}
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "/ban":
		if len(args) < 1 {
			return map[string]string{"message": "Usage: /ban <client_id> [reason]"}
		}
		targetCID := args[0]
		reason := "Rule Violation"
		if len(args) > 1 {
			reason = strings.Join(args[1:], " ")
		}
		if player, exists := players[targetCID]; exists {
			log.Printf("Banning player %s (%s) - Reason: %s", targetCID, player.IP, reason)
			delete(players, targetCID)
			return map[string]string{"message": fmt.Sprintf("Player %s has been banned.", targetCID)}
		} else {
			return map[string]string{"error": fmt.Sprintf("Player %s not found.", targetCID)}
		}
	case "/kick":
		if len(args) < 1 {
			return map[string]string{"message": "Usage: /kick <client_id> [reason]"}
		}
		targetCID := args[0]
		reason := "Kicked by Admin"
		if len(args) > 1 {
			reason = strings.Join(args[1:], " ")
		}
		if player, exists := players[targetCID]; exists {
			log.Printf("Kicking player %s (%s) - Reason: %s", targetCID, player.IP, reason)
			delete(players, targetCID)
			return map[string]string{"message": fmt.Sprintf("Player %s has been kicked.", targetCID)}
		} else {
			return map[string]string{"error": fmt.Sprintf("Player %s not found.", targetCID)}
		}
	case "/list":
		playerList := []string{}
		for pid, p := range players {
			playerList = append(playerList, fmt.Sprintf("%s at position (%.0f, %.0f)", pid, p.X, p.Y))
		}
		if len(playerList) == 0 {
			return map[string]string{"message": "No players online."}
		}
		return map[string]string{"message": "Online Players:\n" + strings.Join(playerList, "\n")}
	case "/stats":
		uptime := time.Since(startTime).Seconds()
		return map[string]string{"message": fmt.Sprintf("Server Stats:\nOnline Players: %d\nTotal Clients: %d\nUptime: %.0f seconds", len(players), len(connections), uptime)}
	case "/help":
		helpText := []string{
			"/ban <client_id> [reason]",
			"/kick <client_id> [reason]",
			"/list",
			"/stats",
			"/help",
		}
		return map[string]string{"message": strings.Join(helpText, "\n")}
	default:
		return map[string]string{"error": fmt.Sprintf("Unknown command: %s", cmd)}
	}
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	ip := r.RemoteAddr
	isAdmin := false

	cid := uuid.New().String()

	mutex.Lock()
	players[cid] = &Player{
		ID:         cid,
		X:          WIDTH / 2,
		Y:          HEIGHT - 100,
		Direction:  "down",
		Moving:     false,
		Hurt:       false,
		Dead:       false,
		Health:     100,
		IP:         ip,
		IsAdmin:    isAdmin,
		Visible:    true,
		LastUpdate: time.Now(),
		LastAttack: time.Now(),
		LastHurt:   time.Now(),
	}
	connections[cid] = conn
	mutex.Unlock()

	log.Printf("Player connected: %s (%s, admin: %t)", cid, ip, isAdmin)

	// Отправка статуса клиенту
	statusMsg := ServerMessage{Type: "status", Status: "ok", CID: cid}
	if isAdmin {
		statusMsg.Status = "admin"
	}
	conn.WriteJSON(statusMsg)

	for {
		var msg ClientMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		mutex.Lock()
		player := players[cid]
		if player == nil {
			mutex.Unlock()
			continue
		}

		switch msg.Type {
		case "handshake":
			if msg.Token != "" {
				username, err := validateJWT(msg.Token)
				if err == nil {
					player.Username = username
					for _, admin := range usersData.Admins {
						if admin == username {
							player.IsAdmin = true
							break
						}
					}
					for _, user := range usersData.Registered {
						if user.Username == username && user.IsAdmin {
							player.IsAdmin = true
							break
						}
					}
					isAdmin = player.IsAdmin
				}
			}
		case "input":
			// Перемещение
			dx := 0.0
			dy := 0.0
			if msg.Left {
				dx = -1
			} else if msg.Right {
				dx = 1
			}
			if msg.Up {
				dy = -1
			} else if msg.Down {
				dy = 1
			}

			moving := dx != 0 || dy != 0
			direction := player.Direction
			if dy < 0 {
				direction = "up"
			} else if dy > 0 {
				direction = "down"
			} else if dx < 0 {
				direction = "left"
			} else if dx > 0 {
				direction = "right"
			}

			player.X += dx * PLAYER_SPEED
			player.Y += dy * PLAYER_SPEED
			player.X = math.Max(0, math.Min(player.X, MAP_WIDTH))
			player.Y = math.Max(0, math.Min(player.Y, MAP_HEIGHT))
			player.Direction = direction
			player.Moving = moving
			player.Attacking = msg.Attack
			player.LastUpdate = time.Now()

			// Атака
			if msg.Attack {
				if time.Since(player.LastAttack) > 600*time.Millisecond {
					projID := fmt.Sprintf("proj_%d", nextProjID)
					nextProjID++
					dirX := 0.0
					dirY := 0.0
					switch direction {
					case "up":
						dirY = -1
					case "down":
						dirY = 1
					case "left":
						dirX = -1
					case "right":
						dirX = 1
					}
					projectiles[projID] = &Projectile{
						ID:         projID,
						X:          player.X,
						Y:          player.Y,
						DX:         dirX * PROJECTILE_SPEED,
						DY:         dirY * PROJECTILE_SPEED,
						OwnerID:    cid,
						LastUpdate: time.Now(),
					}
					player.LastAttack = time.Now()
				}
			}

			// Чат
			if msg.Chat != "" {
				message := strings.TrimSpace(msg.Chat)
				if strings.HasPrefix(message, "/") && isAdmin {
					response := handleCommand(cid, message, isAdmin)
					chatHistory = append(chatHistory, ChatMessage{Sender: 0, Message: response["message"]})
					if response["error"] != "" {
						chatHistory = append(chatHistory, ChatMessage{Sender: 0, Message: response["error"]})
					}
				} else {
					chatHistory = append(chatHistory, ChatMessage{Sender: 0, Message: fmt.Sprintf("[%s]: %s", cid[:8], message)})
				}
			}
		case "pvp_hit":
			if msg.Target != "" {
				if targetPlayer, exists := players[msg.Target]; exists {
					if time.Since(targetPlayer.LastHurt) > 500*time.Millisecond {
						distance := math.Sqrt(math.Pow(player.X-targetPlayer.X, 2) + math.Pow(player.Y-targetPlayer.Y, 2))
						if distance < 50 {
							targetPlayer.Health -= 20
							targetPlayer.Hurt = true
							targetPlayer.LastHurt = time.Now()
							if targetPlayer.Health <= 0 {
								targetPlayer.Dead = true
								targetPlayer.Health = 0
								go respawnPlayer(targetPlayer)
							}
						}
					}
				}
			}
		}
		mutex.Unlock()
	}

	mutex.Lock()
	delete(players, cid)
	delete(connections, cid)
	mutex.Unlock()
	log.Printf("Player disconnected: %s", cid)
}

func respawnPlayer(player *Player) {
	time.Sleep(3 * time.Second)
	player.X = WIDTH / 2
	player.Y = HEIGHT - 100
	player.Health = 100
	player.Dead = false
	player.Hurt = false
}

func gameLoop() {
	ticker := time.NewTicker(16 * time.Millisecond) // Примерно 60 FPS
	defer ticker.Stop()

	for range ticker.C {
		mutex.Lock()

		currentTime := time.Now()

		// Обновление позиций моба
		for _, player := range players {
			var nearestMob *Mob
			minDistance := math.Inf(1)
			for _, mob := range mobs {
				distance := math.Sqrt(math.Pow(mob.X-player.X, 2) + math.Pow(mob.Y-player.Y, 2))
				if distance < minDistance {
					minDistance = distance
					nearestMob = mob
				}
			}
			if nearestMob != nil && minDistance > 0 {
				dx := player.X - nearestMob.X
				dy := player.Y - nearestMob.Y
				nearestMob.X += (dx / minDistance) * MOB_SPEED
				nearestMob.Y += (dy / minDistance) * MOB_SPEED
				nearestMob.X = math.Max(0, math.Min(nearestMob.X, MAP_WIDTH))
				nearestMob.Y = math.Max(0, math.Min(nearestMob.Y, MAP_HEIGHT))
				nearestMob.LastUpdate = currentTime
			}
		}

		// Обновление снарядов
		for id, proj := range projectiles {
			proj.X += proj.DX
			proj.Y += proj.DY
			proj.LastUpdate = currentTime
			if proj.X < 0 || proj.X > MAP_WIDTH || proj.Y < 0 || proj.Y > MAP_HEIGHT {
				delete(projectiles, id)
			}
		}

		// Проверка столкновений снарядов с мобами и игроками
		for projID, proj := range projectiles {
			for mobID, mob := range mobs {
				if math.Abs(proj.X-mob.X) < 32 && math.Abs(proj.Y-mob.Y) < 32 {
					mob.Health -= 10
					delete(projectiles, projID)
					if mob.Health <= 0 {
						delete(mobs, mobID)
						// респаунем нового моба
						spawnRandomMob()
					}
					break
				}
			}

			for playerID, player := range players {
				if proj.OwnerID != playerID {
					if math.Abs(proj.X-player.X) < 32 && math.Abs(proj.Y-player.Y) < 32 {
						player.Health -= 20
						player.Hurt = true
						player.LastHurt = currentTime
						delete(projectiles, projID)
						if player.Health <= 0 {
							player.Dead = true
							player.Health = 0
							go respawnPlayer(player)
						}
						break
					}
				}
			}
		}

		// Готовим игровое состояние
		playersState := make(map[string]interface{})
		for id, p := range players {
			playersState[id] = map[string]interface{}{
				"id":        p.ID,
				"x":         p.X,
				"y":         p.Y,
				"direction": p.Direction,
				"moving":    p.Moving,
				"attacking": p.Attacking,
				"hurt":      p.Hurt,
				"dead":      p.Dead,
				"health":    p.Health,
			}
		}

		mobsState := make(map[string]interface{})
		for id, m := range mobs {
			mobsState[id] = map[string]interface{}{
				"id":        m.ID,
				"x":         m.X,
				"y":         m.Y,
				"direction": m.Direction,
				"health":    m.Health,
			}
		}

		projectilesState := make(map[string]interface{})
		for id, p := range projectiles {
			projectilesState[id] = map[string]interface{}{
				"id": p.ID,
				"x":  p.X,
				"y":  p.Y,
			}
		}

		stateMsg := ServerMessage{
			Type:        "state",
			Players:     playersState,
			Mobs:        mobsState,
			Projectiles: projectilesState,
			ServerTime:  int64(currentTime.Unix()),
			ChatHistory: chatHistory[len(chatHistory)-min(10, len(chatHistory)):],
		}

		// Рассылаем всем клиентам
		for _, conn := range connections {
			conn.WriteJSON(stateMsg)
		}

		mutex.Unlock()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func spawnRandomMob() {
	id := fmt.Sprintf("mob_%d", nextMobID)
	nextMobID++
	mobs[id] = &Mob{
		ID:         id,
		X:          rand.Float64() * MAP_WIDTH,
		Y:          rand.Float64() * MAP_HEIGHT,
		Direction:  "down",
		Health:     100,
		LastUpdate: time.Now(),
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for _, user := range usersData.Registered {
		if user.Username == req.Username {
			http.Error(w, "Username Already Exists", http.StatusConflict)
			return
		}
	}

	newUser := User{
		Username: req.Username,
		Password: req.Password,
		IsAdmin:  false,
	}

	usersData.Registered = append(usersData.Registered, newUser)
	saveUsers()

	token, err := generateJWT(req.Username)
	if err != nil {
		http.Error(w, "Token Generation Error", http.StatusInternalServerError)
		return
	}

	resp := AuthResponse{
		Success: true,
		Message: "Registration Successful!",
		Token:   token,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	mutex.RLock()
	defer mutex.RUnlock()

	for _, user := range usersData.Registered {
		if user.Username == req.Username && user.Password == req.Password {
			token, err := generateJWT(user.Username)
			if err != nil {
				http.Error(w, "Token Generation Error", http.StatusInternalServerError)
				return
			}

			resp := AuthResponse{
				Success: true,
				Message: "Login Success",
				Token:   token,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
}

func generateJWT(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString(jwtSecret)
}

func validateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if username, ok := claims["username"].(string); ok {
			return username, nil
		}
	}
	return "", fmt.Errorf("invalid token")
}

func loadUsers() {
	file, err := os.Open("users.json")
	if err != nil {
		log.Println("Unable to open users.json, initializing defaults.")
		usersData = UsersData{
			Banned:     []string{},
			Admins:     []string{"admin"},
			Registered: []User{},
		}
		saveUsers()
		return
	}
	defer file.Close()

	err = json.NewDecoder(file).Decode(&usersData)
	if err != nil {
		log.Println("Error decoding users.json:", err)
		usersData = UsersData{
			Banned:     []string{},
			Admins:     []string{"admin"},
			Registered: []User{},
		}
		saveUsers()
	}
}

func saveUsers() {
	file, err := os.Create("users.json")
	if err != nil {
		log.Println("Error creating users.json:", err)
		return
	}
	defer file.Close()

	err = json.NewEncoder(file).Encode(usersData)
	if err != nil {
		log.Println("Error saving users.json:", err)
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	loadUsers()
	initMobs()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)

	go gameLoop()

	log.Printf("Starting server on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
