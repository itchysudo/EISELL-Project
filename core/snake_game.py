import tkinter as tk
import random

class SnakeGame:
    def __init__(self, master):
        self.master = master
        self.master.title("Snake Game")

        self.canvas = tk.Canvas(self.master, bg='black', height=400, width=400)
        self.canvas.pack()

        self.snake = [(100, 100), (90, 100), (80, 100)]  # Adjusted initial position to avoid self-collision
        self.food = self.create_food()

        self.snake_dir = 'right'
        self.game_running = True

        self.master.bind("<KeyPress>", self.change_direction)

        self.move_snake()
        self.create_objects()

    def create_objects(self):
        self.canvas.delete(tk.ALL)
        for x, y in self.snake:
            self.canvas.create_rectangle(x, y, x + 10, y + 10, fill='green')
        self.canvas.create_rectangle(self.food[0], self.food[1], self.food[0] + 10, self.food[1] + 10, fill='red')

    def move_snake(self):
        if self.game_running:
            print("Moving snake...")
            x, y = self.snake[0]
            if self.snake_dir == 'up':
                y -= 10
            elif self.snake_dir == 'down':
                y += 10
            elif self.snake_dir == 'left':
                x -= 10
            elif self.snake_dir == 'right':
                x += 10

            new_head = (x, y)
            self.snake = [new_head] + self.snake[:-1]
            print(f"New head position: {new_head}")

            if new_head == self.food:
                print("Food eaten!")
                self.snake.append(self.snake[-1])
                self.food = self.create_food()

            if self.check_collision():
                self.game_running = False
                self.canvas.create_text(200, 200, text="Game Over", fill="white", font=('Helvetica', 24))
            else:
                self.create_objects()
                self.master.after(100, self.move_snake)

    def change_direction(self, event):
        new_dir = event.keysym
        all_directions = {'Up': 'up', 'Down': 'down', 'Left': 'left', 'Right': 'right'}
        opposites = {'up': 'down', 'down': 'up', 'left': 'right', 'right': 'left'}
        if new_dir in all_directions and all_directions[new_dir] != opposites[self.snake_dir]:
            self.snake_dir = all_directions[new_dir]
            print(f"Direction changed to: {self.snake_dir}")

    def create_food(self):
        while True:
            x = random.randint(0, 39) * 10
            y = random.randint(0, 39) * 10
            food = (x, y)
            if food not in self.snake:
                print(f"Food created at: {food}")
                return food

    def check_collision(self):
        x, y = self.snake[0]
        if x < 0 or x >= 400 or y < 0 or y >= 400:
            print("Collision with wall!")
            return True
        if (x, y) in self.snake[1:]:
            print("Collision with self!")
            return True
        return False

def start_snake_game():
    root = tk.Toplevel()
    game = SnakeGame(root)
    root.mainloop()

if __name__ == "__main__":
    start_snake_game()
