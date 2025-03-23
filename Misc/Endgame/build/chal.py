import socketserver
import threading
import random
import math
import numpy as np

def haversine_distance(lat1, lon1, lat2, lon2, unit='km'):
    R_km = 6371.0
    R_mi = 3958.8

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (math.sin(delta_phi / 2.0)**2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0)**2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    if unit == 'km':
        distance = R_km * c
    elif unit == 'mi':
        distance = R_mi * c
    else:
        raise ValueError("Invalid unit. Use 'km' or 'mi'.")

    
    return distance



def initial_bearing(lat1, lon1, lat2, lon2):
    """
    Calculate the initial bearing from point1(lat1, lon1) to point2(lat2, lon2)
    Bearing is from North (0 degrees) turning clockwise.
    """
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_lambda = math.radians(lon2 - lon1)

    y = math.sin(delta_lambda)*math.cos(phi2)
    x = math.cos(phi1)*math.sin(phi2) - math.sin(phi1)*math.cos(phi2)*math.cos(delta_lambda)

    bearing = math.degrees(math.atan2(y, x))
    bearing = (bearing + 360) % 360
    return bearing

BANNER = """

------------------------------------------------------------------------
 ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║██║   ██║██╔██╗ ██║
██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                        
███████╗███╗   ██╗██████╗  ██████╗  █████╗ ███╗   ███╗███████╗          
██╔════╝████╗  ██║██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██╔════╝          
█████╗  ██╔██╗ ██║██║  ██║██║  ███╗███████║██╔████╔██║█████╗            
██╔══╝  ██║╚██╗██║██║  ██║██║   ██║██╔══██║██║╚██╔╝██║██╔══╝            
███████╗██║ ╚████║██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗          
╚══════╝╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝          
------------------------------------------------------------------------
"""

try:
    with open("flag.txt", "r") as f:
        FLAG = f.read().strip()
except FileNotFoundError:
    FLAG = "GrizzCTF{F4k3_fl4g_4_t32t1ng}"

CHALLENGE_INFO = """
[+]███████████████████████████████████████████████████████████████████████████████████████████████████████████████[+]
[+]                                                                                                               [+]
[+]                             Operation End this mans Whole Career - Confidential                                [+]
[+]                                                                                                               [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                                                                                               [+]
[+]     It is the year 2006, and you are an elite intelligence operative working with the FBI to track down an    [+]
[+] Advanced Persistent Threat (APT) individual who was previously believed to be operating abroad. Recent        [+]
[+] intelligence indicates that this individual is temporarily residing in the United States. This active APT     [+]
[+] member is a world renowned world-expert and is well-funded and clever, making him difficult to pin down.        [+]
[+] To locate him, a Stingray (IMSI Catcher) device has been deployed near his known residence in Miami. Over the [+]
[+] past three days, he has been on the move, carrying out clandestine cash pickups and dropoff at various         [+]
[+] inconsipicous locations across the country. Each time he makes a transaction, he activates his mobile device. [+]
[+] Fortunately for us, due to a fundamental design flaw in the device, even if the setting is turned off, it will  [+]
[+] still ping the nearest base-station during it's boot sequence.                                                [+]
[+]                                                                                                               [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                   |*******CONFIDENTIAL*******|                                                [+]
[+] Your task is to solve five triangulation problems to pinpoint his exact locations based on these bearings.     [+]
[+]   - You will be provided the 2 nearest base stations, bearing angle, and the Stingray device location.        [+]
[+]   - Provide the exact (latitude, longitude) coordinates for each location to receive the flag.                 [+]
[+]   - Don't F*ck this up.                                                                                       [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                                                                                               [+]
[+]                                        Good luck, Operator!                                                   [+]
[+]                                                                                                               [+]
[+]███████████████████████████████████████████████████████████████████████████████████████████████████████████████[+]
"""

ADDITIONAL_BASE_STATIONS = [
    {'name': 'BaseStationNY', 'lat': 40.71427, 'lon': -74.00597},
    {'name': 'BaseStationLA', 'lat': 34.05223, 'lon': -118.24368},
    {'name': 'BaseStationCH', 'lat': 41.87811, 'lon': -87.6298},
    {'name': 'BaseStationHO', 'lat': 29.76043, 'lon': -95.3698},
    {'name': 'BaseStationPE', 'lat': 33.44838, 'lon': -112.07404},
    {'name': 'BaseStationPI', 'lat': 39.95258, 'lon': -75.16522},
    {'name': 'BaseStationSA', 'lat': 29.42412, 'lon': -98.49363},
    {'name': 'BaseStationSD', 'lat': 32.71571, 'lon': -117.16472},
    {'name': 'BaseStationD', 'lat': 32.77627, 'lon': -96.7970},
]


def generate_problem():
    # Fixed Stingray device in Miami
    miami_lat, miami_lon = 25.733414, -80.241092

    # Randomly select two distinct base stations
    base_stations = random.sample(ADDITIONAL_BASE_STATIONS, 2)

    # Combine with StingrayMiami
    selected_stations = [
        {'name': 'StingrayMiami', 'lat': miami_lat, 'lon': miami_lon},
        base_stations[0],
        base_stations[1]
    ]

    # Randomly choose a phone location within the USA boundaries (guestimated via ChatGPT)
    while True:
        phone_lat = round(random.uniform(24.396308, 49.384358), 6)
        phone_lon = round(random.uniform(-124.848974, -66.885444), 6)
        # Ensure phone location is at least ~1 km away from any station
        min_distance = min(
            haversine_distance(phone_lat, phone_lon, s['lat'], s['lon'], unit='km')
            for s in selected_stations
        )
        if min_distance >= 1.0:
            break
        else:
            pass

    # Calculate bearings from each station to the phone
    bearings = []
    for s in selected_stations:
        bearing = initial_bearing(s['lat'], s['lon'], phone_lat, phone_lon)
        bearings.append({'name': s['name'], 'bearing': bearing})

    return {
        'towers': selected_stations,
        'phone_location': {'lat': phone_lat, 'lon': phone_lon},
        'bearings': bearings
    }

class TriangulationHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.wfile.write(BANNER.encode())
            self.wfile.flush()

            self.wfile.write(CHALLENGE_INFO.encode())
            self.wfile.flush()

            correct_answers = 0

            for problem_num in range(1, 6):
                problem = generate_problem()
                towers = problem['towers']
                phone_location = problem['phone_location']
                bearings = problem['bearings']

                problem_text = f"\nProblem {problem_num}:\n"
                problem_text += "Three base stations have detected a mobile device. Here are the base station details:\n"
                for station in bearings:
                    si = next((x for x in towers if x['name'] == station['name']), None)
                    if si:
                        problem_text += f"  {station['name']}: Location = ({si['lat']:.6f}, {si['lon']:.6f}), Bearing = {station['bearing']:.2f}°\n"
                problem_text += "These bearings are measured from North, increasing clockwise.\n"
                problem_text += "Find the (latitude, longitude) of the mobile device's location.\n"
                problem_text += "Format: lat,lon (e.g., 12.34,-56.78) make sure to use kilometers for measurements.\n"
                self.wfile.write(problem_text.encode())
                self.wfile.flush()

                self.wfile.write(f"\nEnter your answer for Problem {problem_num}: ".encode())
                self.wfile.flush()

                answer = self.rfile.readline().decode().strip()
                if not answer:
                    self.wfile.write("No input received. Exiting.\n".encode())
                    self.wfile.flush()
                    break

                try:
                    user_lat, user_lon = map(float, answer.split(','))
                except:
                    self.wfile.write("Invalid format. Use lat,lon with decimal points.\n".encode())
                    self.wfile.write("Exiting due to invalid input.\n".encode())
                    self.wfile.flush()
                    break

                expected_lat = phone_location['lat']
                expected_lon = phone_location['lon']
                error_distance = haversine_distance(user_lat, user_lon, expected_lat, expected_lon, unit='km')

                # 1 km margin of error allowed
                if error_distance <= 1.0:
                    correct_answers += 1
                    self.wfile.write("Correct!\n".encode())
                    self.wfile.flush()
                else:
                    self.wfile.write(f"Incorrect. The correct location was ({expected_lat:.6f}, {expected_lon:.6f}).\n".encode())
                    self.wfile.write("You've failed to triangulate the device accurately. Exiting.\n".encode())
                    self.wfile.flush()
                    return

            if correct_answers == 5:
                self.wfile.write(f"\nCongratulations! Here is your flag: {FLAG}\n".encode())
                self.wfile.flush()
            else:
                self.wfile.write("\nSome answers were incorrect. Better luck next time!\n".encode())
                self.wfile.flush()

        except Exception as e:
            logging.error(f"Error handling client {self.client_address}: {e}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def start_server(host='0.0.0.0', port=7777):
    server = ThreadedTCPServer((host, port), TriangulationHandler)
    server.allow_reuse_address = True
    print(f"Triangulation Challenge Server running on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        server.server_close()

if __name__ == "__main__":
    start_server()
