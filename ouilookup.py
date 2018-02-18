#!/usr/bin/env python3
import os
import requests
import sys
import sqlite3
import time


__author__ = "pacmanator"
__email__ = "mrpacmanator@gmail.com"
__version__ = "v1.0"

"""
    OUI-lookup python script.

    Copyright (C) 2018 pacmanator

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""


def get_file():
    """
        Downloads a list of OUIs.
    """
    url = "https://linuxnet.ca/ieee/oui/nmap-mac-prefixes"
    print("[*] Downloading 'nmap-mac-prefixes' from https://linuxnet.ca.")

    # Get the requested file. 
    response = requests.get(url, stream=True)

    # Create the 'vendormacs.txt' file.
    with open("nmap-oui.txt", 'w') as out_file:

        # Write the returned data in chunks of 64 bytes.
        for chunk in response.iter_content(chunk_size=64):
            out_file.write(chunk.decode())

    print("[*] File created.")


def create_mac_address(mac_address):
    return ":".join([mac_address[inx:inx+2] for inx in range(0, len(mac_address), 2)])


def read_nmap_file():
    with open("nmap-oui.txt") as file:
        for line in file.readlines():

            # Split the spaces.
            data = line.split()

            # Store mac prefix.
            mac_prefix = create_mac_address(data[0])

            # Store the whole vendor name.
            vendor_name = " ".join(data[1:len(data)])

            yield mac_prefix, vendor_name


def parse_nmap_file():
    """ Convert nmap-mac-prefixes file to a sqlite3 database. """

    # Check if the nmap-mac-prefixes file exists.
    if not os.path.exists("nmap-mac-prefixes"):
        get_file()

    try:
        conx = create_connection()
        cursor = create_oui_table(conx)
        insert_oui_data(cursor)

    except sqlite3.Error as e:
        print("{0}".format(e))
        conx.close()

        sys.exit()

    except Exception as e:
        print(e)
        sys.exit()


def create_connection():
    """ Create the oui database. """
    try:
        # Creates the database.
        conx = sqlite3.connect("oui.db")
        return conx

    except sqlite3.Error as sqliteError:
        raise sqliteError
    
    return None


def create_oui_table(conx):
    """ Create the oui table. """
    create_table_sql = """ CREATE TABLE IF NOT EXISTS oui (
                                id integer PRIMARY KEY,
                                mac_prefix text NOT NULL,
                                vendor_name text NOT NULL
                     );"""
    try:
        # Create the database cursor.
        cursor = conx.cursor()
        
        # Execute the sql query.
        cursor.execute(create_table_sql)

        return cursor

    except sqlite3.Error as sqliteError:
        cursor.close()
        raise sqliteError

    return None
    

def insert_oui_data(cursor):
    """ Insert the oui data in the oui table. """
    start_time = time.time()
    # Declare sql insert query.
    insert_query = "INSERT OR IGNORE INTO oui (mac_prefix, vendor_name) VALUES(?, ?)"
    
    # Start sql transaction
    cursor.execute("BEGIN TRANSACTION")

    # Count of sql rows.
    rows = 1

    # Bulk insert.
    for mac_prefix, vendor_name in read_nmap_file():
        cursor.execute(insert_query, (mac_prefix, vendor_name))
        rows += 1
    
    # Close transaction.
    cursor.execute("COMMIT")

    # Close cursor.
    cursor.close()

    print("[*] Took {0:3f} sec to insert {1} rows.".format((time.time() - start_time), rows))


def oui_lookup(mac_address):
    """
        Prints the OUI of the provided mac address.
    """
    # Get OUI of the provided macaddress.
    oui = (mac_address.lower()[:8],)
    
    # Connect to database.
    with create_connection() as conx:
        # Create cursor.
        cursor = conx.cursor()

        sql_query = "SELECT vendor_name FROM oui WHERE mac_prefix = ?"
        ret = cursor.execute(sql_query, oui).fetchone()
        
        return oui[0],ret[0] if ret is not None else None

def main():
    if (len(sys.argv) < 2):
        print("Usage: {0} <mac-address>".format(sys.argv[0]))
        sys.exit(0)
        
    if not os.path.exists("oui.db"):
       parse_nmap_file()

    vendor = oui_lookup(sys.argv[1])

    if vendor is not None:
        print("[*] Found vendor: {0} -> {1}".format(vendor[0], vendor[1]))

    else:
        print("[*] Vendor not found.")


if __name__ == "__main__":
    main()

