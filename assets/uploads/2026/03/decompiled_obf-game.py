# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'obf-game.py'
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

global pause
global frame_index
global frame_accumulator
from ctypes import wintypes
import subprocess
import pygame
import random
import sys
import ctypes
import time
import os
import threading
import time
try:
    import requests
except Exception:
    requests = None
import tempfile
SERVER_BASE = 'https://cheat-or-not-cheat-production.up.railway.app'
def _delete_file_later(path, delay=30):
    def _del():
        time.sleep(delay)
        try:
            os.unlink(path)
        except Exception:
            return None
    threading.Thread(target=_del, daemon=True).start()
def fetch_and_show_flag_image():
    # irreducible cflow, using cdg fallback
    """\n    Récupère un token one-time puis télécharge l\'image du flag en streaming\n    vers un fichier temporaire, et l\'ouvre via un viewer externe.\n    Ne garde jamais le flag en clair dans la mémoire du jeu.\n    """
    if requests is None:
        try:
            ctypes.windll.user32.MessageBoxW(0, 'Le module \'requests\' n\'est pas disponible.\nInstalle-le: pip install requests', 'Erreur récupération du flag', 48)
        except Exception:
            print('requests manquant. pip install requests')
        return None
    r = requests.post(SERVER_BASE + '/request_flag_link', timeout=6)
    r.raise_for_status()
    token = (r.json() or {}).get('one_time_token')
    if not token:
        print('Aucun token reçu du serveur')
            return
        url = SERVER_BASE + '/get_flag_image'
        with requests.get(url, params={'token': token}, stream=True, timeout=15) as resp:
            resp.raise_for_status()
            with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmpf:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        tmpf.write(chunk)
                tmp_path = tmpf.name
        if sys.platform.startswith('win'):
            os.startfile(tmp_path)
        else:
            if sys.platform == 'darwin':
                subprocess.Popen(['open', tmp_path])
            else:
                subprocess.Popen(['xdg-open', tmp_path])
        _delete_file_later(tmp_path, delay=30)
            except Exception as e:
                    print('Erreur lors de la récupération du flag:', e)
                        ctypes.windll.user32.MessageBoxW(0, f'Impossible de récupérer le flag via le serveur.\n{e}', 'Erreur', 48)
                            except Exception:
                                pass
def load_flag_image_from_server():
    # irreducible cflow, using cdg fallback
    """\n    Récupère l\'image du flag depuis le serveur et la charge\n    en surface Pygame pour affichage dans la fenêtre du jeu.\n    """
    if requests is None:
        return
    r = requests.post(SERVER_BASE + '/request_flag_link', timeout=6)
    r.raise_for_status()
    token = (r.json() or {}).get('one_time_token')
    if not token:
        print('Aucun token reçu')
            return
        url = SERVER_BASE + '/get_flag_image'
        resp = requests.get(url, params={'token': token}, timeout=10)
        resp.raise_for_status()
        import io
        return pygame.image.load(io.BytesIO(resp.content))
            except Exception as e:
                    print('Erreur de récupération du flag:', e)
                        return None
try:
    import psutil
except Exception:
    psutil = None
SUSPICIOUS_NAMES = ('cheatengine.exe', 'cheatengine-x86_64.exe', 'cheatengine-x86.exe', 'cheatengine64.exe', 'cheatengine', 'cheatengine-x86_64-sse4-avx2.exe')
SUSPICIOUS_DESCRIPTIONS = ('cheat engine',)
def get_file_description_ctypes(path):
    try:
        GetFileVersionInfoSizeW = ctypes.windll.version.GetFileVersionInfoSizeW
        GetFileVersionInfoW = ctypes.windll.version.GetFileVersionInfoW
        VerQueryValueW = ctypes.windll.version.VerQueryValueW
    except Exception:
        return None
    path_w = ctypes.c_wchar_p(path)
    size = GetFileVersionInfoSizeW(path_w, None)
    if not size:
        return
    else:
        buf = ctypes.create_string_buffer(size)
        if not GetFileVersionInfoW(path_w, 0, size, buf):
            return
        else:
            lpt = ctypes.c_void_p()
            lpcb = wintypes.UINT()
            if not VerQueryValueW(buf, ctypes.c_wchar_p('\\\\VarFileInfo\\\\Translation'), ctypes.byref(lpt), ctypes.byref(lpcb)):
                return
            else:
                try:
                    data_ptr = ctypes.cast(lpt, ctypes.POINTER(ctypes.c_ushort * (lpcb.value // 2)))
                    lang, codepage = (data_ptr.contents[0], data_ptr.contents[1])
                except Exception:
                    return None
                key = '\\\\StringFileInfo\\\\%04x%04x\\\\FileDescription' % (lang, codepage)
                if VerQueryValueW(buf, ctypes.c_wchar_p(key), ctypes.byref(lpt), ctypes.byref(lpcb)):
                    desc = ctypes.wstring_at(lpt, lpcb.value)
                    return desc
                else:
                    return None
def detect_cheatengine_process():
    # irreducible cflow, using cdg fallback
    """\n    Retourne (True, nom_ou_description) si un processus suspect est détecté\n    via son nom ou sa description.\n    """
    if psutil:
        for p in psutil.process_iter(['name', 'exe']):
                    name = (p.info.get('name') or '').lower()
                    exe = p.info.get('exe') or ''
                    for s in SUSPICIOUS_NAMES:
                            if s in name:
                                return (True, name)
                            if exe and os.path.exists(exe):
                                desc = get_file_description_ctypes(exe)
                                if desc and any((d in desc.lower() for d in SUSPICIOUS_DESCRIPTIONS)):
                                    return (True, desc)
                                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                                            continue
                    except Exception:
                            pass
                            out = subprocess.check_output('tasklist /FO CSV', shell=True, stderr=subprocess.DEVNULL)
                            out = out.decode(errors='ignore').lower()
                            for s in SUSPICIOUS_NAMES:
                                    if s in out:
                                        return (True, s)
                                            except Exception:
                                                    pass
                                                    return (False, None)
def show_and_exit(message='why are you cheatingggg :(', title='Cheating detected'):
    try:
        ctypes.windll.user32.MessageBoxW(0, message, title, 48)
    except Exception:
        pass
    try:
        pygame.quit()
    except Exception:
        pass
    os._exit(1)
def anti_debug():
    # irreducible cflow, using cdg fallback
    if sys.gettrace() is not None:
        show_and_exit('why are you cheatingggg :( (python debugger detected)')
    if ctypes.windll.kernel32.IsDebuggerPresent():
        show_and_exit('why are you cheatingggg :( (native debugger detected)')
    found, proc = detect_cheatengine_process()
    if found:
        show_and_exit(f'why are you cheatingggg :( ({proc} detected)')
            except Exception:
                    return None
def watchdog():
    while True:
        anti_debug()
        time.sleep(2)
threading.Thread(target=watchdog, daemon=True).start()
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    else:
        return os.path.join(os.path.abspath('.'), relative_path)
pygame.init()
pygame.mixer.init()
score_c = ctypes.c_int(0)
timer_c = ctypes.c_int(20)
font = pygame.font.SysFont('Arial', 48)
font_small = pygame.font.SysFont('Arial', 32)
LARGEUR = 800
HAUTEUR = 600
fenetre = pygame.display.set_mode((LARGEUR, HAUTEUR))
icon = pygame.image.load(resource_path('sprites/yellowbird-midflap.png')).convert_alpha()
pygame.display.set_icon(icon)
pygame.display.set_caption('Cheat or not cheat ?')
NOIR = (0, 0, 0)
BLANC = (255, 255, 255)
ROUGE = (200, 0, 0)
VERT = (0, 200, 0)
taille_oiseau = 32
largeur_tuyau = 60
ecart_tuyau = 160
base_height_target = 80
oiseau_images = [pygame.image.load(resource_path('sprites/yellowbird-downflap.png')).convert_alpha(), pygame.image.load(resource_path('sprites/yellowbird-midflap.png')).convert_alpha(), pygame.image.load(resource_path('sprites/yellowbird-upflap.png')).convert_alpha()]
oiseau_images = [pygame.transform.scale(img, (taille_oiseau, taille_oiseau)) for img in oiseau_images]
background_day = pygame.image.load(resource_path('sprites/background-night.png')).convert()
background_night = pygame.image.load(resource_path('sprites/background-night.png')).convert()
background_day = pygame.transform.scale(background_day, (LARGEUR, HAUTEUR))
background_night = pygame.transform.scale(background_night, (LARGEUR, HAUTEUR))
base_img = pygame.image.load(resource_path('sprites/base.png')).convert_alpha()
base_img = pygame.transform.scale(base_img, (int(base_img.get_width() * (base_height_target / base_img.get_height())), base_height_target))
base_height = base_img.get_height()
base_y = HAUTEUR - base_height
base_segments = LARGEUR // base_img.get_width() + 2
base_x_positions = [i * base_img.get_width() for i in range(base_segments)]
pipe_head_img = pygame.image.load(resource_path('sprites/pipe-green.png')).convert_alpha()
pipe_head_img = pygame.transform.scale(pipe_head_img, (largeur_tuyau, int(pipe_head_img.get_height() * (largeur_tuyau / pipe_head_img.get_width()))))
pipe_head_top_img = pygame.transform.flip(pipe_head_img, False, True)
pipe_part_img = pygame.image.load(resource_path('sprites/pipe-part.png')).convert_alpha()
pipe_part_img = pygame.transform.scale(pipe_part_img, (largeur_tuyau, int(pipe_part_img.get_height() * (largeur_tuyau / pipe_part_img.get_width()))))
pipe_part_top_img = pygame.transform.flip(pipe_part_img, False, True)
son_die = pygame.mixer.Sound(resource_path('audio/die.wav'))
son_point = pygame.mixer.Sound(resource_path('audio/point.wav'))
son_wing = pygame.mixer.Sound(resource_path('audio/wing.wav'))
x_oiseau = 100
y_oiseau = HAUTEUR // 2
gravite = 0.5
vitesse_saut = (-7)
vitesse_oiseau = 0
frame_index = 0
frame_speed = 0.2
frame_accumulator = 0
distance_tuyaux = 350
vitesse_tuyau = 4
tuyaux = []
score = 0
score_c.value = score * 7
last_native_score = score
en_jeu = False
pause = False
victoire = False
message_font = pygame.font.SysFont('Arial', 28, bold=True)
message_text = 'do you think it\'s gonna be that easy ??'
message_lines = []
message_max_width = 600
message_world_x = None
message_y = 300
horloge = pygame.time.Clock()
def get_background():
    cycle = score // 10 % 2
    return background_day if cycle == 0 else background_night
def move_base():
    for i in range(len(base_x_positions)):
        base_x_positions[i] -= vitesse_tuyau
    for i in range(len(base_x_positions)):
        if base_x_positions[i] + base_img.get_width() < 0:
            max_x = max(base_x_positions)
            base_x_positions[i] = max_x + base_img.get_width()
def draw_base():
    for x in base_x_positions:
        fenetre.blit(base_img, (x, base_y))
def creer_tuyau(x_position):
    min_hauteur = 40
    max_hauteur = HAUTEUR - ecart_tuyau - base_height - 40
    if max_hauteur <= min_hauteur:
        max_hauteur = min_hauteur + 1
    hauteur_haut = random.randint(min_hauteur, max_hauteur)
    tuyau_haut = pygame.Rect(x_position, 0, largeur_tuyau, hauteur_haut)
    tuyau_bas = pygame.Rect(x_position, hauteur_haut + ecart_tuyau, largeur_tuyau, HAUTEUR - hauteur_haut - ecart_tuyau - base_height)
    centre = x_position + largeur_tuyau // 2
    return {'rects': (tuyau_haut, tuyau_bas), 'scored': False, 'center_x': centre}
def init_tuyaux():
    tuyaux.clear()
    x_depart = LARGEUR + 500
    for i in range(4):
        tuyaux.append(creer_tuyau(x_depart + i * distance_tuyaux))
def dessiner_oiseau(y, vitesse):
    global frame_accumulator
    global frame_index
    frame_accumulator += frame_speed
    if frame_accumulator >= 1:
        frame_index = (frame_index + 1) % len(oiseau_images)
        frame_accumulator = 0
    image = oiseau_images[frame_index]
    angle = max(min(-vitesse * 3, 25), (-25))
    image_rotatee = pygame.transform.rotate(image, angle)
    rect = image_rotatee.get_rect(center=(x_oiseau, int(y)))
    fenetre.blit(image_rotatee, rect)
    return rect
def afficher_score(val):
    texte = font_small.render(f'Score : {val}', True, NOIR)
    fenetre.blit(texte, (10, 10))
def afficher_timer(val):
    texte = font_small.render(f'Time : {val}', True, ROUGE)
    fenetre.blit(texte, (LARGEUR - 150, 10))
def afficher_pause():
    texte = font.render('PAUSE', True, NOIR)
    sous_texte = font_small.render('Press ESC to resume', True, NOIR)
    rect = texte.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 - 50))
    rect2 = sous_texte.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 + 20))
    fenetre.blit(texte, rect)
    fenetre.blit(sous_texte, rect2)
    pygame.display.update()
def toggle_pause():
    global pause
    pause = not pause
    if pause:
        afficher_pause()
def draw_pipe_seamless(x, y, height, is_top=False):
    head = pipe_head_top_img if is_top else pipe_head_img
    body = pipe_part_top_img if is_top else pipe_part_img
    head_h = head.get_height()
    body_h = body.get_height()
    overlap = 4
    remaining = height - head_h
    if remaining <= 0:
        fenetre.blit(head, (x, y - head_h if is_top else y))
        return
    else:
        step = body_h - overlap
        if is_top:
            head_y = y - head_h
            fenetre.blit(head, (x, head_y))
            cur_y = head_y - step
            while cur_y + body_h > 0:
                fenetre.blit(body, (x, cur_y))
                cur_y -= step
        else:
            fenetre.blit(head, (x, y))
            cur_y = y + head_h
            while cur_y < base_y:
                fenetre.blit(body, (x, cur_y))
                cur_y += step
def page_accueil():
    fenetre.fill((0, 0, 0))
    lignes = ['Welcome to this challenge', 'Will you be able to complete it ?', '', 'Let\'s see....', '', 'Press SPACE to start']
    y = HAUTEUR // 2 - len(lignes) * 30
    for ligne in lignes:
        texte = font.render(ligne, True, (255, 255, 255))
        rect = texte.get_rect(center=(LARGEUR // 2, y))
        fenetre.blit(texte, rect)
        y += 60
    pygame.display.update()
    attente = True
    while attente:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            if event.type == pygame.KEYDOWN and event.key == pygame.K_SPACE:
                    son_wing.play()
                    attente = False
def afficher_victoire():
    fenetre.fill((0, 0, 0))
    titre = font.render('YOU WIN!', True, BLANC)
    rect_titre = titre.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 - 80))
    fenetre.blit(titre, rect_titre)
    message = font_small.render('Good job but it\'s not finished...', True, BLANC)
    fenetre.blit(message, message.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 - 10)))
    message2 = font_small.render('Here is the Level 2', True, BLANC)
    fenetre.blit(message2, message2.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 + 30)))
    objectif_msg = font_small.render('Reach 25 points before the timer runs out!', True, ROUGE)
    fenetre.blit(objectif_msg, objectif_msg.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 + 70)))
    sous_texte = font_small.render('Press SPACE to continue', True, BLANC)
    fenetre.blit(sous_texte, sous_texte.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 + 120)))
    pygame.display.update()
    attente = True
    while attente:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            if event.type == pygame.KEYDOWN and event.key == pygame.K_SPACE:
                    attente = False
                    lancer_niveau_2()
def lancer_niveau_2():
    global pause
    objectif_score = 25
    score2 = 0
    temps_restant = 20
    timer_c.value = 20
    vitesse_oiseau2 = 0
    y_oiseau2 = HAUTEUR // 2
    init_tuyaux()
    pause = False
    countdown = 3
    last_tick = time.time()
    start_time = None
    while True:
        while True:
            now = time.time()
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    pygame.quit()
                    sys.exit()
                if countdown == 0 and event.type == pygame.KEYDOWN and (event.key == pygame.K_SPACE) and (not pause):
                                vitesse_oiseau2 = vitesse_saut
                                son_wing.play()
                if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
                        toggle_pause()
            if countdown > 0:
                fenetre.fill((0, 0, 0))
                texte = font.render(str(countdown), True, BLANC)
                rect = texte.get_rect(center=(LARGEUR // 2, HAUTEUR // 2))
                fenetre.blit(texte, rect)
                pygame.display.update()
                pygame.time.wait(1000)
                countdown -= 1
                if countdown == 0:
                    vitesse_oiseau2 = 0
                    start_time = time.time()
            else:
                if not pause:
                    now = time.time()
                    if now - last_tick >= 1:
                        timer_c.value -= 1
                        last_tick = now
                    temps_restant = timer_c.value
                if not pause:
                    vitesse_oiseau2 += gravite
                    y_oiseau2 += vitesse_oiseau2
                    for t in tuyaux:
                        top_rect, bottom_rect = t['rects']
                        t['rects'] = (top_rect.move(-vitesse_tuyau, 0), bottom_rect.move(-vitesse_tuyau, 0))
                        t['center_x'] -= vitesse_tuyau
                        if not t['scored'] and x_oiseau >= t['center_x']:
                                score2 += 1
                                son_point.play()
                                t['scored'] = True
                    if score2 >= objectif_score:
                        return victoire_level2()
                    else:
                        if tuyaux[(-1)]['rects'][0].x < LARGEUR - distance_tuyaux:
                            tuyaux.append(creer_tuyau(LARGEUR))
                        if tuyaux[0]['rects'][0].x + largeur_tuyau < 0:
                            tuyaux.pop(0)
                        move_base()
                        oiseau_rect = dessiner_oiseau(y_oiseau2, vitesse_oiseau2)
                        for t in tuyaux:
                            top_rect, bottom_rect = t['rects']
                            if oiseau_rect.colliderect(top_rect) or oiseau_rect.colliderect(bottom_rect):
                                son_die.play()
                                return game_over_level2()
                        if y_oiseau2 + oiseau_rect.height / 2 > base_y or y_oiseau2 < 0:
                            son_die.play()
                            return game_over_level2()
                        else:
                            if temps_restant <= 0:
                                return game_over_level2()
                fenetre.blit(get_background(), (0, 0))
                for t in tuyaux:
                    top_rect, bottom_rect = t['rects']
                    draw_pipe_seamless(top_rect.x, top_rect.bottom, top_rect.height, is_top=True)
                    draw_pipe_seamless(bottom_rect.x, bottom_rect.y, bottom_rect.height, is_top=False)
                dessiner_oiseau(y_oiseau2, vitesse_oiseau2)
                draw_base()
                afficher_score(score2)
                afficher_timer(temps_restant)
                if pause:
                    afficher_pause()
                pygame.display.update()
                horloge.tick(60)
def game_over_level2():
    fenetre.fill((0, 0, 0))
    texte = font.render('GAME OVER', True, ROUGE)
    rect = texte.get_rect(center=(LARGEUR // 2, HAUTEUR // 2))
    fenetre.blit(texte, rect)
    pygame.display.update()
    pygame.time.wait(3000)
    pygame.quit()
    sys.exit()
def victoire_level2():
    """\n    Affiche l\'écran de victoire et le flag.\n    Si récupération via Pygame échoue (load_flag_image_from_server() retourne None),\n    on bascule sur le fallback fetch_and_show_flag_image() qui ouvre l\'image\n    dans le viewer natif (os.startfile / open / xdg-open).\n    """
    flag_surface = load_flag_image_from_server()
    fenetre.fill((0, 0, 0))
    titre = font.render('LEVEL 2 COMPLETE!', True, VERT)
    fenetre.blit(titre, titre.get_rect(center=(LARGEUR // 2, 100)))
    sous = font_small.render('Here is your reward', True, BLANC)
    fenetre.blit(sous, sous.get_rect(center=(LARGEUR // 2, 160)))
    if flag_surface:
        max_width, max_height = (600, 300)
        rect = flag_surface.get_rect()
        if rect.width > max_width or rect.height > max_height:
            ratio = min(max_width / rect.width, max_height / rect.height)
            new_size = (int(rect.width * ratio), int(rect.height * ratio))
            flag_surface = pygame.transform.smoothscale(flag_surface, new_size)
            rect = flag_surface.get_rect()
        rect.center = (LARGEUR // 2, HAUTEUR // 2 + 50)
        fenetre.blit(flag_surface, rect)
        info_text = 'Press ESC to quit'
    else:
        try:
            fetch_and_show_flag_image()
            erreur = font_small.render('Image ouverte dans votre viewer externe.', True, BLANC)
            fenetre.blit(erreur, erreur.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 + 20)))
            info_text = 'Check the opened image and press ESC to quit'
        except Exception as e:
            print('Fallback fetch_and_show_flag_image() failed:', repr(e))
            erreur2 = font_small.render('Impossible d\'ouvrir le flag automatiquement.', True, ROUGE)
            fenetre.blit(erreur2, erreur2.get_rect(center=(LARGEUR // 2, HAUTEUR // 2 + 20)))
            info_text = 'See console for details. Press ESC to quit'
    info = font_small.render(info_text, True, BLANC)
    fenetre.blit(info, info.get_rect(center=(LARGEUR // 2, HAUTEUR - 50)))
    pygame.display.update()
    attente = True
    while attente:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
                    pygame.quit()
                    sys.exit()
page_accueil()
init_tuyaux()
en_jeu = True
while True:
    native_val = score_c.value // 7
    if native_val!= last_native_score:
        score = int(native_val)
        last_native_score = native_val
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            pygame.quit()
            sys.exit()
        if victoire and event.type == pygame.KEYDOWN and (event.key == pygame.K_ESCAPE):
                    pygame.quit()
                    sys.exit()
        if en_jeu and (not pause) and (event.type == pygame.KEYDOWN) and (event.key == pygame.K_SPACE):
                        vitesse_oiseau = vitesse_saut
                        son_wing.play()
        if not en_jeu and (not victoire) and (event.type == pygame.KEYDOWN) and (event.key == pygame.K_SPACE):
                        init_tuyaux()
                        score = 0
                        score_c.value = score * 7
                        last_native_score = score
                        y_oiseau = HAUTEUR // 2
                        vitesse_oiseau = 0
                        en_jeu = True
                        pause = False
                        message_world_x = None
                        son_wing.play()
        if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE and (not victoire) and en_jeu:
                        toggle_pause()
    if en_jeu and (not pause) and (not victoire):
                vitesse_oiseau += gravite
                y_oiseau += vitesse_oiseau
                for t in tuyaux:
                    top_rect, bottom_rect = t['rects']
                    t['rects'] = (top_rect.move(-vitesse_tuyau, 0), bottom_rect.move(-vitesse_tuyau, 0))
                    t['center_x'] -= vitesse_tuyau
                    if not t['scored'] and x_oiseau >= t['center_x']:
                            score += 1
                            score_c.value = score * 7
                            last_native_score = score
                            son_point.play()
                            t['scored'] = True
                            if score == 6666:
                                victoire = True
                                en_jeu = False
                if tuyaux[(-1)]['rects'][0].x < LARGEUR - distance_tuyaux:
                    tuyaux.append(creer_tuyau(LARGEUR))
                if tuyaux[0]['rects'][0].x + largeur_tuyau < 0:
                    tuyaux.pop(0)
                move_base()
                oiseau_rect = dessiner_oiseau(y_oiseau, vitesse_oiseau)
                for t in tuyaux:
                    top_rect, bottom_rect = t['rects']
                    if oiseau_rect.colliderect(top_rect) or oiseau_rect.colliderect(bottom_rect):
                        son_die.play()
                        en_jeu = False
                if y_oiseau + oiseau_rect.height / 2 > base_y or y_oiseau < 0:
                    son_die.play()
                    en_jeu = False
    if victoire:
        afficher_victoire()
    else:
        fenetre.blit(get_background(), (0, 0))
        for t in tuyaux:
            top_rect, bottom_rect = t['rects']
            draw_pipe_seamless(top_rect.x, top_rect.bottom, top_rect.height, is_top=True)
            draw_pipe_seamless(bottom_rect.x, bottom_rect.y, bottom_rect.height, is_top=False)
        dessiner_oiseau(y_oiseau, vitesse_oiseau)
        draw_base()
        afficher_score(score)
        if pause:
            afficher_pause()
    pygame.display.update()
    horloge.tick(60)