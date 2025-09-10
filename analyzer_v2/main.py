import tkinter as tk
from analyzer.app import Application

def main():
    root = tk.Tk()
    app = Application(root)
    
    # Center the window
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width/2) - (1200/2)
    y = (screen_height/2) - (900/2)
    root.geometry(f'1200x900+{int(x)}+{int(y)}')
    
    # Make window resizable
    root.resizable(True, True)
    
    # Configure grid weights
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()