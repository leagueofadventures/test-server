package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"time"
)

type Player struct {
	X, Y    float64
	ID      string
	Health  int
	LastShot time.Time
}

type Mob struct {
	X, Y    float64
	ID      int
	Health  int
	Target  string
}

type Projectile struct {
	X, Y    float64
	DX, DY  float64
	ID      int
	Owner   string
}

type GameState struct {
	Players     map[string]*Player
	Mobs        []*Mob
	Projectiles []*Projectile
}

var (
	gameState = GameState{
		Players:     make(map[string]*Player),
		Mobs:        []*Mob{},
		Projectiles: []*Projectile{},
	}
	clients   = make(map[string]net.Conn)
	mu        sync.Mutex
	nextMobID = 0
	nextProjID = 0
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()
	fmt.Println("Server started on :" + port)

	// Генерация мобов
	go func() {
		for {
			time.Sleep(5 * time.Second)
			mu.Lock()
			mob := &Mob{
				X:      400,
				Y:      300,
				ID:     nextMobID,
				Health: 3,
				Target: "1", // Цель - игрок 1
			}
			nextMobID++
			gameState.Mobs = append(gameState.Mobs, mob)
			mu.Unlock()
		}
	}()

	// Игровой цикл
	go gameLoop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		playerID := fmt.Sprintf("%d", len(clients)+1)
		clients[playerID] = conn
		gameState.Players[playerID] = &Player{
			X:      100 + float64(len(clients)*100),
			Y:      300,
			ID:     playerID,
			Health: 10,
		}
		go handleClient(conn, playerID)
	}
}

func handleClient(conn net.Conn, playerID string) {
	defer conn.Close()
	defer func() {
		mu.Lock()
		delete(clients, playerID)
		delete(gameState.Players, playerID)
		mu.Unlock()
	}()

	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			break
		}
		var action map[string]interface{}
		json.Unmarshal(buffer[:n], &action)

		mu.Lock()
		player := gameState.Players[playerID]
		if move, ok := action["move"].(map[string]interface{}); ok {
			if dx, ok := move["x"].(float64); ok {
				player.X += dx * 5
			}
			if dy, ok := move["y"].(float64); ok {
				player.Y += dy * 5
			}
			// Ограничение границ
			if player.X < 0 { player.X = 0 }
			if player.X > 750 { player.X = 750 }
			if player.Y < 0 { player.Y = 0 }
			if player.Y > 550 { player.Y = 550 }
		}
		if shoot, ok := action["shoot"].(bool); ok && shoot && time.Since(player.LastShot) > 500*time.Millisecond {
			player.LastShot = time.Now()
			proj := &Projectile{
				X:     player.X + 25,
				Y:     player.Y + 25,
				DX:    0,
				DY:    -10, // Стрельба вверх
				ID:    nextProjID,
				Owner: playerID,
			}
			nextProjID++
			gameState.Projectiles = append(gameState.Projectiles, proj)
		}
		mu.Unlock()
	}
}

func gameLoop() {
	ticker := time.NewTicker(16 * time.Millisecond) // ~60 FPS
	defer ticker.Stop()
	for range ticker.C {
		mu.Lock()
		// Движение мобов
		for _, mob := range gameState.Mobs {
			if target, ok := gameState.Players[mob.Target]; ok {
				dx := target.X - mob.X
				dy := target.Y - mob.Y
				dist := math.Sqrt(dx*dx + dy*dy)
				if dist > 0 {
					mob.X += (dx / dist) * 2
					mob.Y += (dy / dist) * 2
				}
			}
		}

		// Движение проектилиев
		for i := len(gameState.Projectiles) - 1; i >= 0; i-- {
			proj := gameState.Projectiles[i]
			proj.X += proj.DX
			proj.Y += proj.DY
			if proj.X < 0 || proj.X > 800 || proj.Y < 0 || proj.Y > 600 {
				gameState.Projectiles = append(gameState.Projectiles[:i], gameState.Projectiles[i+1:]...)
			}
		}

		// Столкновения проектилиев с мобы
		for i := len(gameState.Projectiles) - 1; i >= 0; i-- {
			proj := gameState.Projectiles[i]
			for j := len(gameState.Mobs) - 1; j >= 0; j-- {
				mob := gameState.Mobs[j]
				if math.Abs(proj.X-mob.X) < 20 && math.Abs(proj.Y-mob.Y) < 20 {
					mob.Health--
					if mob.Health <= 0 {
						gameState.Mobs = append(gameState.Mobs[:j], gameState.Mobs[j+1:]...)
					}
					gameState.Projectiles = append(gameState.Projectiles[:i], gameState.Projectiles[i+1:]...)
					break
				}
			}
		}

		// Столкновения мобов с игроками
		for _, mob := range gameState.Mobs {
			for _, player := range gameState.Players {
				if math.Abs(player.X-mob.X) < 40 && math.Abs(player.Y-mob.Y) < 40 {
					player.Health--
					if player.Health <= 0 {
						// Игрок умер, можно добавить логику респавна
					}
					// Удалить моба после атаки
					mob.Health = 0
				}
			}
		}

		// Удалить мертвых мобов
		for i := len(gameState.Mobs) - 1; i >= 0; i-- {
			if gameState.Mobs[i].Health <= 0 {
				gameState.Mobs = append(gameState.Mobs[:i], gameState.Mobs[i+1:]...)
			}
		}

		// Отправка состояния всем клиентам
		stateJSON, _ := json.Marshal(gameState)
		for _, conn := range clients {
			conn.Write(stateJSON)
		}
		mu.Unlock()
	}
}
