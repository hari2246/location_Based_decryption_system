import geocoder

# Get current location based on your IP
g = geocoder.ip('me')

if g.ok:
    print("Your approximate location:")
    print(f"Latitude: {g.latlng[0]}")
    print(f"Longitude: {g.latlng[1]}")
else:
    print("Could not determine location.")
