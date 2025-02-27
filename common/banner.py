from common.constants import START_TIMESTAMP


# Banners. These banners are merged using zip() and printed side-by-side.
# Keep all additional whitespace in these multiline strings.
def print_banner(info=None):
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

    if info:
        print(" ----------------------------------------------------------------------------------------")
        if isinstance(info, str):
            info = info.replace("\n", "\n|  ")
            print(f"|  {info}")
        elif isinstance(info, list):
            for line in info:
                line = line.replace("\n", "\n|  ")
                print(f"|  {line}")
        print(f"|")
        print(" ----------------------------------------------------------------------------------------")
    print(f"Launch Timestamp: {START_TIMESTAMP.split('.')[0]}")
    print()
