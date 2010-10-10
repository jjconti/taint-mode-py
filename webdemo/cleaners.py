def clean_osi(s):
    return s.split(';')[0]
    

if __name__ == '__main__':
    dataset = ['fish and chips', 'potatoes', 'potatoes; ls', ';ls', 'butter;']
    
    for d in dataset:
        print 'original: ', d, 'cleaned: ', clean_osi(d), "tainted?", d != clean_osi(d)