import gzip


with(open("webpage_new.dat",'rb')) as f:
    data = f.read()
    txt = gzip.decompress(data)
    txt_dec = txt.decode('utf-8')
    # txt_dec.replace('/uploads','www.weislank.com/uploads')
    print(txt_dec)
    lines = txt_dec.splitlines();
    with open("webpage.html",'w',encoding='UTF-8') as f2:
        for line in lines:
            if line.find('/uploads') != -1:
                line = line.replace('/uploads','www.weislank.com/uploads')
                print(line)
            if line.find('/static') != -1:
                line = line.replace('/static','www.weislank.com/static')
                print(line)
            f2.write(line)
            f2.write('\n')