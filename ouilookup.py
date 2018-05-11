#!/usr/bin/env python3
import argparse
import codecs
import os
import requests
import sys
import sqlite3
import time


__author__ = "pacmanator"
__email__ = "mrpacmanator at gmail dot com"
__version__ = "v1.0"


def get_file():
    """
        Downloads a list of OUIs.
    """
    url = "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf;hb=HEAD"
    print("[!] File w_manuf.txt not found!.\n")
    print("[*] Downloading 'wireshark manufacturer list'")

    try:
        # Get the requested file. 
        response = requests.get(url, stream=True)

        # Create the 'vendormacs.txt' file.
        with codecs.open("w_manuf.txt", 'wb') as out_file:

            bytes_w = 0
            # Write the returned data in chunks of 64 bytes.
            for chunk in response.iter_content(chunk_size=128):
                # Bytes read to file.
                bytes_w += len(chunk)
                print("Bytes read: {:d}\r".format(bytes_w), end="\r")
                out_file.write(chunk)
            
        print("\n[*] File created.")
        
    except KeyboardInterrupt:
        print("User requested an exit.")
        print("Shutting down...")
        sys.exit(0)
    
    except Exception as e:
        raise Exception(e)


def read_wireshark_file():
    with codecs.open("w_manuf.txt", "r", "utf-8") as file:
        for line in file.readlines():
            # Skip the coments.
            if (line[0] == "#") or (len(line) == 1):
                continue

            data = line.split("\t")

            if len(data[0]) == 20:
                mac = data.pop(0)
                data.insert(0, mac[:17])

            if len(data) > 2:
                full_vendor_name = data.pop(2)
                data.insert(1, full_vendor_name)

            yield data[0], data[1]


def create_connection():
    """ Create the oui database or establish a connection to it. """
    try:
        # Creates the database.
        return sqlite3.connect("oui.db")

    except sqlite3.Error as sqliteError:
        raise sqlite3.Error(sqliteError)
    
    except Exception as e:
        raise Exception(e)
    
    return None


def create_oui_table():
    """ Create the oui table. """
    create_table_sql = """ CREATE TABLE IF NOT EXISTS oui (
                                id integer PRIMARY KEY,
                                mac_prefix text NOT NULL,
                                vendor_name text NOT NULL
                     );"""
    try:
        # Create the database cursor.
        cursor = create_connection().cursor()
        
        # Execute the sql query.
        cursor.execute(create_table_sql)

    except sqlite3.Error as sqliteError:
        cursor.close()
        raise sqlite3.Error(sqliteError)
    
    except Exception as e:
        cursor.close()
        raise Exception(e)
    
    return cursor
    

def insert_oui_data():
    """ Insert the oui data in the oui table. """
    start_time = time.time()
    cursor = create_oui_table()

    # Declare sql insert query.
    insert_query = "INSERT OR IGNORE INTO oui (mac_prefix, vendor_name) VALUES(?, ?)"
    
    try:
        # Start sql transaction
        cursor.execute("BEGIN TRANSACTION")

        # Count of sql rows.
        rows = 1
        print("[*] Inserting data...")
        # Bulk insert.
        for mac_prefix, vendor_name in read_wireshark_file():
            cursor.execute(insert_query, (mac_prefix, vendor_name))
            rows += 1
        
        # Close transaction.
        cursor.execute("COMMIT")

        print("[*] Took {0:3f} sec to insert {1} rows.".format((time.time() - start_time), rows))

    except sqlite3.Error as sqliteError:
        raise sqlite3.Error(sqliteError)
    
    except Exception as e:
        raise Exception(e)
    
    finally:
        cursor.close()
    


def parse_w_manuf_file():
    """ Convert w_manuf.txt file to a sqlite3 database. """

    # Check if the w_manuf file exists.
    if not os.path.exists("w_manuf.txt"):
        get_file()

    insert_oui_data()


def oui_lookup(mac_address):
    """
        Prints the OUI of the provided mac address.
    """
    # Get OUI of the provided macaddress.
    oui = (mac_address.upper()[:8],)
    
    # Connect to database.
    with create_connection() as conx:
        # Create cursor.
        cursor = conx.cursor()

        sql_query = "SELECT vendor_name FROM oui WHERE mac_prefix = ?"
        ret = cursor.execute(sql_query, oui).fetchone()
        
        return oui[0],ret[0] if ret is not None else None


def check_mac_address(mac_address):
    """ Replaces MAC address '-' delimiter with a semicolon ':'."""
    if mac_address.find("-") > 0:
        return mac_address.replace("-", ":")
    
    if (mac_address.find(":") == -1) or (len(mac_address) >= 6):
        return create_mac_address(mac_address)
    
    return mac_address


def create_mac_address(mac_address):
    return ":".join([mac_address[inx:inx + 2] for inx in range(0, len(mac_address), 2)])


def get_oui(mac_address):
    mac_address = check_mac_address(mac_address)

    vendor = oui_lookup(mac_address)

    if vendor[1] is not None:
        print("[*] Found vendor: {0} -> {1}".format(vendor[0], vendor[1]))

    else:
        print("[*] Vendor not found.")


def bulker(file):
    """ Parses a txt file containing MAC addresses """
    if not os.path.exists(file):
        print("File {0} doesn't exists.".format(file), file=sys.stderr)
        print("Exiting...")
        sys.exit()
    
    with open(file) as mac_list:
        for line in mac_list.read().split("\n"):
            print("Querying {0}".format(line))
            get_oui(line)
    

def main():    
    parser = argparse.ArgumentParser(description="OUI lookup script.")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", dest="mac_address", type=str, action="store",
                        help="Mac address.")

    group.add_argument("-f", dest="file", type=str, action="store",
                        help="File containing a list of MAC addresses",
                        default=None)

    args = parser.parse_args()

    if not os.path.exists("oui.db"):
       parse_w_manuf_file()

    if args.file is not None:
        bulker(args.file)
    else:
        get_oui(args.mac_address)


if __name__ == "__main__":
    main()
