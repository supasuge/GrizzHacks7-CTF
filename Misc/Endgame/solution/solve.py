#!/usr/bin/python3
from pwn import *
import re
import math
import numpy as np
from scipy.optimize import least_squares
import sys
def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371.0
    phi1, phi2 = np.radians(lat1), np.radians(lat2)
    d_phi = np.radians(lat2 - lat1)
    d_lambda = np.radians(lon2 - lon1)

    a = (np.sin(d_phi/2.0)**2 +
         np.cos(phi1)*np.cos(phi2)*np.sin(d_lambda/2.0)**2)
    c = 2*np.arctan2(np.sqrt(a), np.sqrt(1-a))
    return R*c

def initial_bearing(lat1, lon1, lat2, lon2):
    """
    Calculate initial bearing from (lat1, lon1) to (lat2, lon2).
    Bearing is from North, increasing clockwise, in [0, 360).
    """
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_lambda = math.radians(lon2 - lon1)
    y = math.sin(d_lambda)*math.cos(phi2)
    x = math.cos(phi1)*math.sin(phi2) - math.sin(phi1)*math.cos(phi2)*math.cos(d_lambda)
    bearing = math.degrees(math.atan2(y, x))
    bearing = (bearing + 360) % 360
    return bearing

def angle_diff(a, b):
    """
    Compute the minimal angular difference between angles a and b, both in [0,360).
    Result will be in [-180, 180], we can take absolute if needed.
    """
    diff = (a - b + 180) % 360 - 180
    return diff

def bearing_residuals(vars, towers):
    lat_guess, lon_guess = vars
    res = []
    for (t_lat, t_lon, given_bearing) in towers:
        calc_bearing = initial_bearing(t_lat, t_lon, lat_guess, lon_guess)
        diff = angle_diff(calc_bearing, given_bearing)
        res.append(diff)  # difference in degrees
    return res

def triangulate_nonlinear(towers):
    """
    Use nonlinear least squares to find lat/lon that minimize bearing differences.
    towers: [(lat, lon, bearing), (lat, lon, bearing), (lat, lon, bearing)]
    """
    # Initial guess: average tower position
    avg_lat = sum(t[0] for t in towers)/len(towers)
    avg_lon = sum(t[1] for t in towers)/len(towers)

    result = least_squares(bearing_residuals, [avg_lat, avg_lon],
                           args=(towers,),
                           ftol=1e-12, xtol=1e-12, max_nfev=5000)

    if result.success:
        lat_res, lon_res = result.x
        return round(lat_res, 6), round(lon_res, 6)
    else:
        return None, None

def main():
    context.log_level = 'info'
    if len(sys.argv) != 2 or sys.argv[1] not in ['local', 'docker', 'remote']:
        print("Usage: python3 solve.py {local|docker|remote}|<host IP> <host Port>")
        sys.exit(1)
    PORT=7777
    if sys.argv[1].lower() == "local":
        HOST = 'localhost'
    elif sys.argv[1].lower() == "docker":
        HOST='172.17.0.4'
    

    try:
        io = remote(HOST, PORT)
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    # Receive banner and challenge info
    try:
        banner = io.recvuntil(b"Good luck, Operator!", timeout=10)
        print(banner.decode())
    except:
        print("Failed to receive initial data.")
        io.close()
        return

    for problem_num in range(1, 6):
        try:
            problem_data = io.recvuntil(f"Enter your answer for Problem {problem_num}: ".encode(), timeout=10)
            print(problem_data.decode())
        except:
            print("Failed to receive problem data.")
            io.close()
            return

        # Regex for bearings scenario:
        pattern = r"(\w+): Location = \(([-\d\.]+), ([-\d\.]+)\), Bearing = ([\d\.]+)°"
        towers_data = re.findall(pattern, problem_data.decode())

        if len(towers_data) != 3:
            print("Parsing towers failed.")
            io.sendline(b"0.00,0.00")
            io.close()
            return

        towers = []
        for tower in towers_data:
            name, lat_str, lon_str, bearing_str = tower
            lat, lon, bearing = float(lat_str), float(lon_str), float(bearing_str)
            towers.append((lat, lon, bearing))

        # Triangulate using nonlinear optimization on bearings
        phone_lat, phone_lon = triangulate_nonlinear(towers)

        if phone_lat is None or phone_lon is None:
            # If we fail, send a dummy answer
            io.sendline(b"0.00,0.00")
            io.close()
            return

        answer = f"{phone_lat},{phone_lon}"
        print(f"Sending Answer for Problem {problem_num}: {answer}")
        io.sendline(answer.encode())

        # Get response
        try:
            resp = io.recvline(timeout=5)
        except:
            print("No response after sending answer.")
            io.close()
            return

        if b"Correct!" in resp:
            print(resp.decode().strip())
            continue
        else:
            # Print what we got and exit
            print(resp.decode().strip())
            try:
                print(io.recvall(timeout=5).decode())
            except:
                pass
            io.close()
            return

    # After all correct, receive the flag
    try:
        final_message = io.recvall(timeout=10).decode()
        print(final_message)
    except:
        pass
    io.close()

if __name__ == "__main__":
    main()
