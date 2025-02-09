##Static Variables
MSG = input.txt
KEY = key.txt
ENC = encrypted.txt
DEC = decrypted.txt
IMG = image.ppm
RAND = random_numbers.txt
img_enc = enc_image.ppm
PYFILE = AES.py

##Targets

encrypt:
	python3 $(PYFILE) -e $(MSG) $(KEY) $(ENC)

decrypt:
	python3 $(PYFILE) -d $(ENC) $(KEY) $(DEC)

image:
	python3 $(PYFILE) -i $(IMG) $(KEY) $(img_enc)

random:
	python3 $(PYFILE) -r 5 $(KEY) $(RAND)

test: encrypt decrypt image random
	python3 $(PYFILE) -i $(img_enc) $(KEY) test.ppm
	diff $(IMG) test.ppm

clean:
	rm -f $(ENC) $(DEC) *.zip

all: clean encrypt decrypt

#add HW02 <last name><first name>.zip with *.pdf, and DES.py
submit:
	zip -r hw05_Panchagnula_Raghava.zip hw05_Panchagnula_Raghava.pdf $(PYFILE) $(img_enc)

.PHONY: encrypt decrypt test
