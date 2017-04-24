var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);

app.get('/', function(req, res){
  res.sendFile(__dirname + '/index.html');
});

io.on('connection', function(socket){
  console.log('a user connected');
});

http.listen(3000, function(){
  console.log('listening on *:3000');
});

var fetch = require('node-fetch');
var pcap = require('pcap'),
    pcap_session = pcap.createSession('', 'udp'),
    lastIp = '0.0.0.0',
    filterList = [
        '192.168.',
        '173.194.68.189',
        '254.128',
        '172.217.7.164',
        '172.217.7.164',
        '216.58.219.206',
        '172.217.0.35'
    ],
    storedList = [],
    totalRequests = 0;

pcap_session.on('packet', function(raw_packet) {

    // find packet source IP
    var packet = pcap.decode.packet(raw_packet),
        sourceIp = packet.payload.payload.saddr.addr.join('.');

    // return if IP matches lastIp
    if (sourceIp.match(lastIp)) {
        //console.log('matches last');
    } else {
        // check if ip matches anything in filter list
        let filtered = filterList.find(function(listItem) {
            return sourceIp.match(listItem);
        });
        // log IP if not filtered
        if (typeof filtered === 'undefined') {
            let stored = storedList.find(function(listItem) {
                return sourceIp.match(listItem.ip);
            });
            if (typeof stored === 'undefined') {
                console.log('not in list: ');
                fetch('http://freegeoip.net/json/' + sourceIp).then(function(response) {
                    if (response.status !== 200) {
                        console.log('Looks like there was a problem. Status Code: ' + response.status);
                        return;
                    }

                    // Examine the text in the response
                    response.json().then(function(data) {
                        console.log(data);
                        storedList.push(data);
                        io.emit('address', JSON.stringify(data));
                    });
                }).catch(function(err) {
                    console.log('Fetch Error :-S', err);
                });
                totalRequests += 1;
            } else {
                console.log('in list:');
                console.log(stored);
                io.emit('address', JSON.stringify(stored));
            }

        }
    }
    if (sourceIp !== '') {
        lastIp = sourceIp;
        console.log(`Total requests: ${totalRequests}`);
    }
});
