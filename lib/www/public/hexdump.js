// Hexdump.js 0.1.1
// (c) 2011 Dustin Willis Webber
// Hexdump is freely distributable under the MIT license.
// For all details and documentation:
// http://github.com/mephux/hexdump.js

var Hexdump;

Hexdump = (function() {

    // Hexdump Initializer
    // data => The string payload.
    // options => hexdump configurations
    function Hexdump(data, options) {
        var self = this;
        self.hexdump = [];
        self.hex = false;
        self.options = {
            container: options.container || ''
            , width: options.width || 16
            , byteGrouping: options.byteGrouping || 0
            , ascii: options.ascii
            , lineNumber: options.lineNumber
            , endian: options.endian || 'big'
            , html: options.html
            , base: options.base || 'hexadecimal'
            , nonPrintable: options.nonPrintable || '.'
            , style: {
                lineNumberLeft: options.style.lineNumberLeft || ''
                , lineNumberRight: options.style.lineNumberRight || ':'
                , stringLeft: options.style.stringLeft || '|'
                , stringRight: options.style.stringRight || '|'
                , hexLeft: options.style.hexLeft || ''
                , hexRight: options.style.hexRight || ''
                , hexNull: options.style.hexNull || '.'
                , stringNull: options.style.stringNull || ' '
            }
        };

        if (self.options.base == 'hex') {
            self.hex = true;
        } else if (self.options.base == 'hexadecimal') {
            self.hex = true;
        };

        // Check for the line number option and turn it off
        // if not set unless it has been explicitly turned
        // off by the user.
        var ln = self.options.lineNumber;
        if (typeof ln == "undefined" || ln == null) {
            self.options.lineNumber = true;
        };

        var askey = self.options.ascii;
        if (typeof askey == "undefined" || askey == null) {
            self.options.ascii = false;
        };


        var html = self.options.html;
        if (typeof html == "undefined" || html == null) {
            self.options.html = true;
        };

        if (self.endian != ('little' || 'big')) {
            self.endian = 'big';
        };

        // Make sure spacing is within proper range.
        if (self.options.byteGrouping > data.length) {
            self.options.byteGrouping = data.length;
        };
        self.options.byteGrouping--;

        // Make sure width is within proper range.
        if (self.options.width > data.length) {
            self.options.width = data.length;
        };

        // Base padding
        self.padding = {
            hex: 4,
            dec: 5,
            bin: 8
        };

        // Base conversion logic
        switch(self.options.base) {
            case 'hexadecimal': case 'hex': case 16:
            self.setNullPadding(self.padding.hex);
            self.baseConvert = function(characters) {

                for (var i=0; i < characters.length; i++) {
                    return self.addPadding(characters[i].charCodeAt(0).toString(16), self.padding.hex);
                };

            }; break;
            case 'decimal': case 'dec': case 10:
            self.setNullPadding(self.padding.dec);
            self.baseConvert = function(characters) {

                for (var i=0; i < characters.length; i++) {
                    return self.addPadding(characters[i].charCodeAt(0), self.padding.dec);
                };

            }; break;
            case 'binary': case 'bin': case 2:
            self.setNullPadding(self.padding.bin);
            self.baseConvert = function(characters) {
                for (var i=0; i < characters.length; i++) {
                    var ddx = characters[i].charCodeAt(0), r = "";

                    for (var bbx = 0; bbx < 8; bbx++) {
                        r = (ddx%2) + r; ddx = Math.floor(ddx/2);
                    };

                    return self.addPadding(r, self.padding.bin);
                };
            }; break;
            default:
                self.options.base = 'hex';
                self.hex = true;

                self.setNullPadding(self.padding.hex);
                self.baseConvert = function(characters) {

                    for (var i=0; i < characters.length; i++) {
                        return self.addPadding(characters[i].charCodeAt(0).toString(16), self.padding.hex);
                    };

                };
        };

        var regex = new RegExp('.{1,' + this.options.width + '}', 'g');

        self.data = data.match(regex);

        self.nullCount = (self.options.width - self.data[self.data.length - 1].length);

        self.hexCounter = 0;

        self.stringCounter = 0;

        for (var i=0; i < self.data.length; i++) {
            var tempData = self.process(self.data[i]);

            self.hexdump.push({
                data: tempData.data,
                string: tempData.string,
                length: self.data[i].length,
                missing: (self.options.width - self.data[i].length)
            });
        };

        self.dump();
    }

    Hexdump.prototype.dump = function() {
        var self = this;

        self.output = '';
        for (var i=0; i < self.hexdump.length; i++) {

            if (self.options.lineNumber) {
                var tempLineNumberStyle = '';
                tempLineNumberStyle += self.options.style.lineNumberLeft;

                var currentLineCount = (i * self.options.width); //.toString(16);
                var temLineCount = 8 - currentLineCount.toString().length;
                for (var l=0; l < temLineCount; l++) {
                    tempLineNumberStyle += '0';
                };

                tempLineNumberStyle += currentLineCount;
                tempLineNumberStyle += self.options.style.lineNumberRight + ' ';

                if (self.options.html) {
                    self.output += '<span id="line-number">'+tempLineNumberStyle+'</span>';
                } else {
                    self.output += tempLineNumberStyle;
                };
            };

            var spacingCount = 0;
            var breakPoint = Math.floor(self.options.width / 2);

            self.output += self.options.style.hexLeft;

            for (var x=0; x < self.hexdump[i].data.length; x++) {

                if (spacingCount == self.options.byteGrouping) {
                    if (x == self.hexdump[i].data.length - 1) {
                        self.output += self.hexdump[i].data[x];
                    } else {
                        self.output += self.hexdump[i].data[x] + ' ';
                    };
                    spacingCount = 0;
                } else {
                    self.output += self.hexdump[i].data[x];
                    spacingCount++;
                };
            };

            self.output += self.options.style.hexRight;

            self.appendString(self.hexdump[i]);
            self.output += "\n";
        };

        var hexdump_container = document.getElementById(this.options.container);
        hexdump_container.innerHTML = this.output;
    };

    Hexdump.prototype.appendString = function(data) {
        var self = this;
        self.output += ' ' + self.options.style.stringLeft;
        self.output += data.string;
        self.output += self.options.style.stringRight;
    };

    Hexdump.prototype.splitNulls = function(code) {
        var split = [];
        var buffer = "";

        if (code && code.length > 2) {
            for (var cc = 0; cc < code.length; cc++) {
                var tempi = cc + 1;

                if (tempi % 2 == 0) {

                    buffer += code[cc].toString();
                    split.push(buffer);

                    buffer = "";

                } else {

                    buffer += code[cc].toString();

                };

            };
        };

        return split;
    };

    Hexdump.prototype.process = function(data) {
        var self = this;
        var stringArray = [];
        var hexArray = [];

        for (var i=0; i < data.length; i++) {
            if (self.options.html) {

                var code = self.baseConvert(data[i]);

                if (self.hex) {
                    var split = self.splitNulls(code);

                    for (var y = 0; y < split.length; y++) {
                        hexArray.push('<span data-hex-id="' + self.hexCounter + '">' +
                            split[y] + '</span>');
                    };

                } else {

                    hexArray.push('<span data-hex-id="' + self.hexCounter + '">' +
                        code + '</span>');

                };

                stringArray.push('<span data-string-id="' + self.hexCounter + '">' +
                    self.checkForNonPrintable(data[i]) + '</span>');

            } else {

                var code = self.baseConvert(data[i]);

                if (self.hex) {
                    var split = self.splitNulls(code);

                    for (var y = 0; y < split.length; y++) {
                        hexArray.push(split[y]);
                    };

                } else {
                    hexArray.push(code);
                };

                stringArray.push(self.checkForNonPrintable(data[i]));

            };

            self.hexCounter++;
        };

        if (self.hex) {
            var splitHexWidth = self.options.width * 2;
        } else {
            var splitHexWidth = self.options.width;
        };

        if (hexArray.length < splitHexWidth) {
            var amount = (splitHexWidth - hexArray.length);

            for (var i=0; i < amount; i++) {
                var nullHex = '';

                if (self.options.html) {
                    nullHex = '<span data-hex-null="true">' + self.options.style.hexNull + '</span>';
                } else {
                    nullHex = self.options.style.hexNull;
                };

                hexArray.push(nullHex);
            };
        };

        if (stringArray.length < self.options.width) {
            var stringAmount = self.options.width - stringArray.length;
            for (var i=0; i < stringAmount; i++) {
                var nullString = '';

                if (self.options.html) {
                    nullString = '<span data-string-null="true">' + self.options.style.stringNull + '</span>';
                } else {
                    nullString = self.options.style.stringNull;
                };


                stringArray.push(nullString);
            };
        };

        return { data: hexArray, string: stringArray.join('') };
    };

    Hexdump.prototype.setNullPadding = function(padding) {
        var self = this;

        var hexNull = self.options.style.hexNull[0]
        self.options.style.hexNull = "";

        if (self.hex) {
            padding = padding / 2;
        };

        for (var p=0; p < padding; p++) {
            self.options.style.hexNull += hexNull;
        };
    };

    Hexdump.prototype.addPadding = function(ch, padding) {
        var self = this, length = ch.toString().length, pad = '';

        for (var i=0; i < (padding - length); i++) {
            pad += '0'
        };

        if (self.options.endian == 'big') {
            return pad + ch;
        } else {
            return ch + pad;
        };
    };

    Hexdump.prototype.checkForNonPrintable = function(character) {
        var self = this;
        var c = character.charCodeAt(0).toString(16);

        if (c == 0x9) {
            return '.'
        } else if (c == 0x7F) {
            return '.'
        } else if (c.length > 2 && self.options.ascii) {
            return '.'
        } else {
            return character;
        };

    };

    return Hexdump;
})();
