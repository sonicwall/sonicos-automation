from common.constants import VERSION_STRING, START_TIMESTAMP


# Banners. These banners are merged using zip() and printed side-by-side.
# Keep all additional whitespace in these multiline strings.
def print_banner():
    # Keep all additional whitespace in these multiline strings.
    banner_text1 = """
             `'.----.`         
     '*yZgB#@@@@@@@@@@@@BRUL^,`
   !$@@@@@@@@@@@@BOwx~_        
  .@@@@@@@@@#M]:     
  `@@@@@@@d~     
   ^@@@@@u       
    -d@@@y       
      "G@@V      
         *G$)    
            "*_  
    """.split("\n")

    # Keep all additional whitespace in these multiline strings.
    banner_text2 = '''




.d88888b                    oo          dP   dP   dP          dP dP 
88.    "'                               88   88   88          88 88 
`Y88888b. .d8888b. 88d888b. dP .d8888b. 88  .8P  .8P .d8888b. 88 88 
      `8b 88'  `88 88'  `88 88 88'  `"" 88  d8'  d8' 88'  `88 88 88 
d8'   .8P 88.  .88 88    88 88 88.  ... 88.d8P8.d8P  88.  .88 88 88 
 Y88888P  `88888P' dP    dP dP `88888P' 8888' Y88'   `88888P8 dP dP 

                                                                         '''.split("\n")

    # Zip the two multi-line strings together and print a line from each.
    for row in zip(banner_text1, banner_text2):
        print(row[0] + " " + row[1])

    intro_text = f"                 -- Bulk Change: Force Password Change Script (v{VERSION_STRING}) --"
    print(intro_text)
    print(" ----------------------------------------------------------------------------------------")
    # print(f"|                                 !! IMPORTANT !!")
    print(f"|  This tool automates the task of forcing all local users to update their password.")
    print(f"|  It uses SonicOS API to pull the list of users and update the flag to force a password change.")
    print(f"|")
    print(" ----------------------------------------------------------------------------------------")
    print(f"v{VERSION_STRING} | Launch Timestamp: {START_TIMESTAMP.split('.')[0]}")
    print()
