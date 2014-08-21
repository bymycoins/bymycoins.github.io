
    var bitcore = require('bitcore');
    var oracle_base = 'https://www.realitykeys.com'
    var oracle_api_base = oracle_base + '/api/v1';
    var oracle_view_base = oracle_base + '/fact/';
    var oracle_param_string = '?accept_terms_of_service=current';

    function assert(val, description) {
        if (!val) {
            console.log("ASSERT FAIL: "+description);
        }
    }

    // Return sanitized pubkey, or null if it doesn't look like a proper pubkey
    // TODO: If we get uncompressed stuff here, compress it.
    function format_pubkey(txt) {
        txt = txt.toLowerCase();
        // TODO: If passed uncompressed keys, compress them instead of failing
        if (/[0-9a-f]{66}/.test(txt)) {
            return txt;
        } else {
            return null;
        }
    }

    function format_fact_id(txt) {
        return parseInt(txt) + '';
    }

    function format_address(txt) {
        // NB We allow any prefix to allow for various alt-coins and things
        if (/[0-9A-Za-z]{20,40}/.test(txt)) {
            return txt;
        } else {
            return null;
        }
    }

    function test_format_sanitization() {

        var addr = format_address('thing%thing');
        assert((addr == null), 'script tags addr format to null');
        assert((format_address('1923abcdez92') == null) , 'base 58 check less than 20 chars fails');
        var valid_addr = '01234567891232323201234567892323232';
        assert(valid_addr == format_address(valid_addr) , 'base 58 check returns orig address if pattern generally ok');
        assert(format_pubkey('abcdj') == null, 'pubkey with non-hex characters returns null' );

        assert(format_pubkey('A0B0C0D0E0') == null, 'pubkey with non-hex characters returns null' );
        var valid_pubkey = '02d8cb2a0ea3cadc894d19081fb241723f0a69c3819b035d0ae587a11849ba9b28';
        assert(valid_pubkey == format_pubkey(valid_pubkey), 'valid pubkey returns sanitized identically');

        assert(valid_pubkey == format_pubkey('02D8CB2A0Ea3cadc894d19081fb241723f0a69c3819b035d0ae587a11849ba9b28'), 'capital letters in hex come back lower-cased');

    }

    function test_mnemonic_handling() {

        var mne = new Mnemonic(128);
        var words = mne.toWords();
        var mne_hex = mne.toHex();
        assert(words.length == 12, '128-bit mnemonic makes 12 words');

        var mne2 = new Mnemonic(128);
        var mne2_hex = mne2.toHex()

        assert( (mne_hex != mne2_hex), 'Mnemonic makes a different hex result every time');

        var fixed_words = ["love", "ache", "bother", "cross", "fought", "swim", "brave", "rare", "hey", "neither", "paint", "bought"];

        var fixed_hex = '19958d7ae02536984de76050569555c1';
        var fixed_mne = new Mnemonic(fixed_words);
        assert( fixed_mne.toHex() == fixed_hex, 'Mnemonic loaded from previous output returns the same hex as before');

        var round_trip_mne = seed_to_mnemonic(fixed_hex);
        assert( fixed_words.join(' ') == round_trip_mne.toWords().join(' '), 'Mnemonic can be recreated from seed');

        var dodgy_words = [
            'asdf1', 'asdf2', 'asdf3', 'asdf4', 'asdf5', 'asdf6', 'asdf7', 'asdf8', 'asdf9', 'asdf10', 'asdf11', 'asdf12'
        ];
        var dodgy_mne = new Mnemonic(dodgy_words);
        assert(('ffffffffffffffffffffffffffffffff' == dodgy_mne.toHex()), 'Fed words it does not understand Mnemonic returns ffffffffffffffffffffffffffffffff');
        
    }

    function test_hash_to_contract() {

        var a_pub = '02d8cb2a0ea3cadc894d19081fb241723f0a69c3819b035d0ae587a11849ba9b28';
        var b_pub = '0254694936f88db742069686bd964020e3c453120044ae35fb2a91ed556b93e1e7';
        var fact_id = '2';

        assert(hash_to_contract('asdf') == null, 'Badly formatted hash returns null');

        var valid_hash = '#' + a_pub + '-' + b_pub + '-' + fact_id + '-' + 'tbtc';
        var c = hash_to_contract(valid_hash);
        assert(c != null, 'Valid hash produces non-null contract object');
        assert(c['yes_user_pubkey'] == a_pub, 'Item 1 in hash produces contract object with yes_user_pubkey');
        assert(c['no_user_pubkey'] == b_pub, 'Item 2 in hash produces contract object with no_user_pubkey');
        assert(c['id'] == fact_id, 'Item 3 produces contract object with correct fact id');
        assert(c['is_testnet'], 'Item 4 as tbtc produces is_testnet as true');

        var valid_hash_2 = '#' + a_pub + '-' + b_pub + '-' + fact_id + '-' + 'btc';
        var c2 = hash_to_contract(valid_hash_2);
        assert(!c2['is_testnet'], 'Item 4 as not tbtc produces is_testnet as false');

    }

    function test_script_monkey_patches() {

        var a_pub = new Buffer('02d8cb2a0ea3cadc894d19081fb241723f0a69c3819b035d0ae587a11849ba9b28', 'hex');
        var yes_pub = new Buffer('02585eca9b441b0e17b12145f2d73ac7dd8da1eae7cdb4022db6b78f224db3bdc9', 'hex');
        var b_pub = new Buffer('0254694936f88db742069686bd964020e3c453120044ae35fb2a91ed556b93e1e7', 'hex');
        var no_pub = new Buffer('037545a3b495208ba67328773361ca5c0037352839d3c634251b540e91b61e0fd8', 'hex');

        var s = Script.createMultisigGroups( [2,2], [ [a_pub, yes_pub], [b_pub, no_pub] ], {}); 
        var chunks = s.chunks;
        assert(chunks.length == 13, '13 chunks in 2-grouip pattern');
        assert(chunks[0] == Opcode.map.OP_IF, 'chunk 0 OP_IF in 2-group pattern');
        assert(chunks[1] != Opcode.map.OP_IF, 'chunk 1 OP_IF in 2-group pattern');
        assert(chunks[chunks.length-1] == Opcode.map.OP_ENDIF, 'last chunk OP_ENDIF in 2-group pattern');

        var s = Script.createMultisigGroups( [2,2,2], [ [a_pub, yes_pub], [b_pub, no_pub], [yes_pub, no_pub] ], {}); 
        var chunks = s.chunks;
        //assert(chunks.length == 13, '13 chunks in 2/2 pattern');
        assert(chunks[0] == Opcode.map.OP_IF, 'chunk 0 OP_IF in 3-group pattern');
        assert(chunks[1] == Opcode.map.OP_IF, 'chunk 1 OP_IF in 3-group pattern');
        assert(chunks[chunks.length-1] == Opcode.map.OP_ENDIF, 'last chunk OP_ENDIF in 3-group pattern');

    }

    function test_transaction_cycle() {

        var yes_user_mnemonic = 'glad everywhere alone rabbit daily bank date goal force glorious some freely';
        var yes_user_mne = new Mnemonic(yes_user_mnemonic.split(' ')); 
        var yes_user_seed = yes_user_mne.toHex();
        var yes_user_key_obj = key_for_new_seed(yes_user_seed);
        var yes_user_privkey = yes_user_key_obj['priv'];
        var yes_user_pubkey = yes_user_key_obj['pub'];
        assert(yes_user_pubkey == '03b1e8aba06d96273de138cb8f672ef93b3bdefd9dc18d6c038e4eb8a766778ad3', 'Yes user pubkey as expected');

        var no_user_mnemonic = 'manage wound those decide rule sadness confusion cheese house decision mutter girl';
        var no_user_mne = new Mnemonic(no_user_mnemonic.split(' ')); 
        var no_user_seed = no_user_mne.toHex();
        var no_user_privkey_obj = key_for_new_seed(no_user_seed);
        var no_user_privkey = no_user_privkey_obj['priv']
        var no_user_pubkey = no_user_privkey_obj['pub']
        assert(no_user_pubkey == '0213e0a3f741cd305571366ee3d30bfd819bd95b6f0d8dea0ee13a10dc3f6cf4e6', 'No user pubkey as expected');;

        var cash_out_address = 'mrYtQCHVLFrvrkt7Wf3TEajsZ9UwDMDKCs';

        // The following are previously-settled Reality Keys runkeeper facts
        // The resulting object should be the same as what you would get if you fetched the json from the api

        // https://www.realitykeys.com/api/v1/runkeeper/251/?accept_terms_of_service=current
        var yes_fact = {"no_pubkey": "03ead85d26a8339abffabe420a5cc23d9a12a0d005a7d248c80c0d43cf969236e3", "settlement_date": "2014-07-23", "objection_period_secs": 86400, "human_resolution_scheduled_datetime": null, "user": "edochan", "measurement": "cumulative_distance", "evaluation_method": "ge", "is_user_authenticated": true, "objection_fee_satoshis_paid": 0, "machine_resolution_scheduled_datetime": "2014-07-23 00:00:00", "goal": "123", "created_datetime": "2014-07-23 03:30:47", "winner": "Yes", "value": "123", "id": 251, "source": "runkeeper", "yes_pubkey": "03ef92fd0593af4e10de665d1b25703a76af84349becdf6830b290a010db837460", "activity": "walking", "objection_fee_satoshis_due": 1000000, "winner_privkey": "L4URPwQTLbuZjhZZB3VCway3AGtMHGtxiY1JpjwSj7EKgwvF8oYa"};

        // https://www.realitykeys.com/api/v1/runkeeper/252/?accept_terms_of_service=current
        var no_fact = {"no_pubkey": "02c5671e3ec059bd200665d227e99e3f3f0f28ecdf848c4bfb5de408e5def8300a", "settlement_date": "2014-07-23", "objection_period_secs": 86400, "human_resolution_scheduled_datetime": null, "user": "edochan", "measurement": "cumulative_distance", "evaluation_method": "ge", "is_user_authenticated": true, "objection_fee_satoshis_paid": 0, "machine_resolution_scheduled_datetime": "2014-07-23 00:00:00", "goal": "12300", "created_datetime": "2014-07-23 09:11:05", "winner": "No", "value": "12300", "id": 252, "source": "runkeeper", "yes_pubkey": "02f70abb10f616d102b67ea0cc5f4887df642771c4dce5ba838ac88e465210dd64", "activity": "walking", "objection_fee_satoshis_due": 1000000, "winner_privkey": "L3iW65EC59fvWjsRz2TNPjBtueyBt2mkGE59LdG5nAf463YTRD45"}




        // testnet contract for fact 251 (yes)
        var c251t = yes_fact; // NB This will have more fields filled than we would have in reality
        c251t['is_testnet'] = true;
        c251t['yes_user_pubkey'] = yes_user_pubkey;
        c251t['no_user_pubkey'] = no_user_pubkey;
        c251t['is_testnet'] = true;

        // old method with only the two groups and no user+user unlocking
        //var c251t_fund_address = p2sh_address(c251t, false);
        //assert('2N3gsvXbFd5UmjPTwHy1gNyLQ8SXPqMVqrU' == c251t_fund_address, 'fact 251 gives us the expected funding address');

        c251t_fund_address = p2sh_address(c251t);
        assert('2MxivUngEKfZVUmCv3b9ff4qmoDhRHTENcn' == c251t_fund_address, 'fact 251 gives us the expected funding address with the extra user-user branch');

        // mainnet version of the same thing
        var c251m = c251t;
        c251m['is_testnet'] = false;
        assert(p2sh_address(c251m) != c251t_fund_address, 'Without testnet flag p2sh address is different to testnet version');

        // These will be actual testnet transactions, but once we have run the test once they will have been spent
        var funded1 = 0.01;
        var funded2 = 0.02;
        var fund_txid_1 = 'deebc555268396f24d46575b56df839316525796497809b476e29d17c1e2c0ef'; 
        var fund_txid_2 = 'aaf895c26bd32b4fb575b878ad51b7d189edfdd425f95a8026c24de8d93b98c1';

        // Normally we would pull the balance from blockr.
        // We then use it to populate the balance field of the contract
        c251t['balance'] = 0.03;

        var demo_unspent_blockr = {
            "status": "success",
            "data": {
                "address": "2N3gsvXbFd5UmjPTwHy1gNyLQ8SXPqMVqrU",
                "unspent": [
                    {
                        "tx": "deebc555268396f24d46575b56df839316525796497809b476e29d17c1e2c0ef",
                        "amount": "0.01000000",
                        "n": 0,
                        "confirmations": 1,
                        "script": "a914728b52d98256323232481fa1eff352dfbcb2f78687"
                    },
                    {
                        "tx": "aaf895c26bd32b4fb575b878ad51b7d189edfdd425f95a8026c24de8d93b98c1",
                        "amount": "0.02000000",
                        "n": 1,
                        "confirmations": 1,
                        "script": "a914728b52d98256323232481fa1eff352dfbcb2f78687"
                    }
                ],
                "with_unconfirmed": true
            },
            "code": 200,
            "message": ""
        };
        var demo_unspent_txes = demo_unspent_blockr['data']['unspent'];

        var c251t_tx_hex = hex_for_claim_execution(cash_out_address, yes_user_privkey, c251t['winner_privkey'], demo_unspent_txes[0], c251t);
        var c251t_tx_hex_2 = hex_for_claim_execution(cash_out_address, yes_user_privkey, c251t['winner_privkey'], demo_unspent_txes[0], c251t);
        assert(c251t_tx_hex != c251t_tx_hex_2, 'Hex should be different each time, due to randomness in signatures');

        var c251t_tx = tx_for_claim_execution(cash_out_address, yes_user_privkey, c251t['winner_privkey'], demo_unspent_txes[0], c251t);
        var chunks = c251t_tx['ins'][0].getScript().chunks;
        assert(0 == chunks[0].toString(), 'sig starts with an OP_0 for a buggy CHECK_MULTISIG to munch on');
        assert(chunks[1].toString('hex').length > 50, 'first sig > 50 chars (TODO: when lib gets deterministic k, check expected val');
        assert(chunks[2].toString('hex').length > 50, 'first sig > 50 chars (TODO: when lib gets deterministic k, check expected val');
        assert(81 == chunks[3].toString(), 'after sigs we have a 1');
        assert(81 == chunks[4].toString(), 'after sigs we have another 1 for the first branch');
        assert(chunks[5].toString('hex').length > 100, 'ends with a big old redeem script');
        
        /*
        TODO: Work out how to propagate the errors for this
        try {
            var c251t_tx_hex_wrong = hex_for_claim_execution(cash_out_address, no_user_privkey, c251t['winner_privkey'], demo_unspent_txes[0], c251t);
console.log(c251t_tx_hex_wrong);
            assert(false, 'Trying to claim with the wrong key combination should raise an error');
        } catch( err) {
            assert(true, 'Trying to claim with the wrong key combination should raise an error');
        }
        */


        var c251t_tx_user = tx_for_claim_execution(cash_out_address, yes_user_privkey, no_user_privkey, demo_unspent_txes[0], c251t);
        var chunks = c251t_tx_user['ins'][0].getScript().chunks;
        assert(0 == chunks[0].toString(), 'sig starts with an OP_0 for a buggy CHECK_MULTISIG to munch on');
        assert(chunks[1].toString('hex').length > 50, 'first sig > 50 chars (TODO: when lib gets deterministic k, check expected val');
        assert(chunks[2].toString('hex').length > 50, 'first sig > 50 chars (TODO: when lib gets deterministic k, check expected val');
        assert(0 == chunks[3].toString(), 'after sigs we have a noop');
        assert(chunks[4].toString('hex').length > 100, 'ends with a big old redeem script');



        // testnet contract for fact 251 (yes)
        var c252t = no_fact; // NB This will have more fields filled than we would have in reality
        c252t['is_testnet'] = true;
        c252t['yes_user_pubkey'] = yes_user_pubkey;
        c252t['no_user_pubkey'] = no_user_pubkey;
        c252t['is_testnet'] = true;

        // old method with only the two groups and no user+user unlocking
        //var c252t_fund_address = p2sh_address(c252t, false);
        //assert('2N3gsvXbFd5UmjPTwHy1gNyLQ8SXPqMVqrU' == c252t_fund_address, 'fact 252 gives us the expected funding address');

        c252t_fund_address = p2sh_address(c252t);
        assert('2Mtr3ge4kcA8rffWQdwfkcEYfuzyZJ956A2' == c252t_fund_address, 'fact 252 gives us the expected funding address with the extra user-user branch');
        assert(c251t_fund_address != c252t_fund_address, 'Yes fact produces a different funding address to a different no fact');

        // mainnet version of the same thing
        var c252t_tx_hex = hex_for_claim_execution(cash_out_address, no_user_privkey, c252t['winner_privkey'], demo_unspent_txes[0], c252t);
        var c252t_tx_hex_2 = hex_for_claim_execution(cash_out_address, no_user_privkey, c252t['winner_privkey'], demo_unspent_txes[0], c252t);
        assert(c252t_tx_hex != c252t_tx_hex_2, 'Hex should be different each time, due to randomness in signatures');

        var c252t_tx = tx_for_claim_execution(cash_out_address, no_user_privkey, c252t['winner_privkey'], demo_unspent_txes[0], c252t);
        var chunks = c252t_tx['ins'][0].getScript().chunks;
        assert(0 == chunks[0].toString(), 'sig starts with an OP_0 for a buggy CHECK_MULTISIG to munch on');
        assert(chunks[1].toString('hex').length > 50, 'first sig > 50 chars (TODO: when lib gets deterministic k, check expected val');
        assert(chunks[2].toString('hex').length > 50, 'first sig > 50 chars (TODO: when lib gets deterministic k, check expected val');
        assert(0 == chunks[3].toString(), 'after sigs we have a 1');
        assert(81 == chunks[4].toString(), 'after sigs we have a 0 for the first branch');
        assert(chunks[5].toString('hex').length > 100, 'ends with a big old redeem script');
 






        //console.log("Made hex:");
        //console.log(c251t_tx_hex);

        // Sending this resulted in:
        // txid: '5b834f6c1d750f60deec7c83da918832d55f9c290429c838df734f9ed2a32a3c'
        // raw tx: '0100000001efc0e2c1179de276b4097849965752169383df565b57464df296832655c5ebde00000000fd2501004730440220795bf7bc4529f2ffcdd625d9eb2e3769b9ce3eee7cca2b0d6c868bbc1ea34dd502206dc62551a96f9c43f4e0eaa288db65a27efd9dc529c45b2d2485f1966ce205ca01473044022003fcb9e1eeac11fd4c1a2696cdcdc2f1f1e81e1501cc5d56113d18888986df800220290d43ce410bd445b3ea25916eb4799ed702dfb9394bf954442d13213c6523c601514c9163522103b1e8aba06d96273de138cb8f672ef93b3bdefd9dc18d6c038e4eb8a766778ad32103ef92fd0593af4e10de665d1b25703a76af84349becdf6830b290a010db83746052ae6752210213e0a3f741cd305571366ee3d30bfd819bd95b6f0d8dea0ee13a10dc3f6cf4e62103ead85d26a8339abffabe420a5cc23d9a12a0d005a7d248c80c0d43cf969236e352ae68ffffffff01301b0f00000000001976a9147906f703d0774e8f4b2fb0b716b6352e86687dfc88ac00000000'

    }

    function run_tests() {

        test_format_sanitization();
        test_hash_to_contract();
        test_mnemonic_handling();
        test_transaction_cycle();
        test_script_monkey_patches();
        console.log('All tests complete');

    }

    // From
    // https://github.com/ggozad/mnemonic.js/issues/1
    function seed_to_mnemonic(hex_seed) {
        var random = [];
        for(var i=0;i<hex_seed.length;i++){
            var integer = parseInt(hex_seed.slice(8*i,i*8+8),16);
            if (!isNaN(integer) ){
                random.push(integer);
            }
        }
        var m  = new Mnemonic();
        m.random = random;
        return m;
    }

    function store_contract(c, is_update) {

        //console.log("storing:");
        //console.log(c);
        contract_store = {
            'contracts': {},
            'default': null
        }

        // We sometimes have a lot of data here - just store the bare minimum to recreate the contract
        var storeme = {};
        storeme['yes_user_pubkey'] = c['yes_user_pubkey'];
        storeme['no_user_pubkey'] = c['no_user_pubkey'];
        storeme['address'] = c['address'];
        storeme['id'] = c['id'];

        p2sh_addr = c['address'];
        contract_json_str = localStorage.getItem('contract_store');
        if (contract_json_str) {
            contract_store = JSON.parse(contract_json_str);
        }
        if (!is_update) {
            if (contract_store['contracts'][p2sh_addr]) {
                alert('already there');
                return; // Already there
            }
        }
        //contract_store['contracts'][p2sh_addr] = storeme;
        contract_store['contracts'][p2sh_addr] = c;
        contract_store['default'] = p2sh_addr;

        localStorage.setItem('contract_store', JSON.stringify(contract_store));

    }

    function is_contract_stored(p2sh_addr) {

        contract_json_str = localStorage.getItem('contract_store');
        if (!contract_json_str) {
            return false;
        }
        contract_store = JSON.parse(contract_json_str);
        if (contract_store['contracts'][p2sh_addr]) {
            return true; // Already there
        }
        return false;

    }

    function store_athlete(a) {

        athlete_store = {
            'athletes': {},
            'default': null
        }

        athlete_json_str = localStorage.getItem('athlete_store');
        if (athlete_json_str) {
            athlete_store = JSON.parse(athlete_json_str);
        }
        athlete_store['athletes'][a] = a;

        // Always set the most recently stored to the default
        athlete_store['default'] = a;

        localStorage.setItem('athlete_store', JSON.stringify(athlete_store));

    }

    // Return a hash of athlete names and true/false for default or not
    function load_athletes() {
       //console.log('loading a');
        athlete_json_str = localStorage.getItem('athlete_store');
        if (!athlete_json_str) {
            return [];
        }
        var athlete_store = JSON.parse(athlete_json_str);
        if (!athlete_store['athletes']) {
            return [];
        }
        var default_athlete = athlete_store['default'];
        ret = {};
        for (a in athlete_store['athletes']) {
            var is_default = (a == default_athlete); 
            ret[a] = is_default; 
        }
        return ret;

    }

    function load_default_athlete() {

        athletes = load_athletes();
        if (athletes.length == 0) {
            return null;
        }
        for (a in athletes) {
            if (athletes[a]) {
                return a;
            }
        }
        return null;

    }

    function store_key(k) {

        //console.log("storing:");
        //console.log(k);
        var key_store = {
            'seeds': {},
            'default': null
        }

        var seed = k['seed'];
        var key_json_str = localStorage.getItem('key_store');
        if (key_json_str) {
            key_store = JSON.parse(key_json_str);
        }
        key_store['seeds'][seed] = k;
        key_store['default'] = seed;
        //console.log(JSON.stringify(key_store));

        localStorage.setItem('key_store', JSON.stringify(key_store));
        return true;

    }

    function stored_priv_for_pub(pub) {

        var key_json_str = localStorage.getItem('key_store');
        if (key_json_str == '') {
            return null;
        }
        key_store = JSON.parse(key_json_str);
        seeds = key_store['seeds'];
        for (var s in seeds) {
            if (!seeds.hasOwnProperty(s)) {
                continue;
            }
            var k = seeds[s];
            if (k['pub'] == pub) {
                return k['priv'];
            }
            //console.log("no match for "+pub+": "+k['pub']);
            //console.log(k);
        }
        return null;

    }

    function load_default_key() {

        key_json_str = localStorage.getItem('key_store');
        if (key_json_str) {
            //console.log("got key store");
            var key_store = JSON.parse(key_json_str);
            var default_entry = key_store['default'];
            return key_store['seeds'][default_entry];
        }
        return null;

    }

    function load_stored_key(seed) {

        key_json_str = localStorage.getItem('key_store');
        if (key_json_str) {
            //console.log("got key store");
            var key_store = JSON.parse(key_json_str);
            if (key_store['seeds'][seed]) {
                return key_store['seeds'][seed];
            } 
        }
        return null;

    }

    function handle_mnemonic_change(inp) {

        /* 
        Possiblities:
        - empty mnemonic
        - invalid mnemonic
        - existing mnemonic
        - new mnemonic 
        */

        var ng = false;

        var mnemonic_text = inp.val();
        if (mnemonic_text == '') {
            ng = true;
        } 

        var words;
        if (!ng) {
            words = mnemonic_text.split(' ');
            if (words.length != 12) {
                ng = true;
            }
        }

        if (!ng) {
            var mne = new Mnemonic(words); 
            var seed = mne.toHex();
            if (load_stored_key(seed)) {
                // already good
                $('body').addClass('mnemonic-created-and-confirmed');
                return true;
            } 
        }

        $('body').removeClass('mnemonic-created-and-confirmed');
        if (ng) {
            $('#public-key').text('');
            $('.public-key-display').hide();
            $('#confirm-mnemonic-button').attr('disabled', 'disabled');
        } else {
            $('#confirm-mnemonic-button').removeAttr('disabled');
            //$('.public-key-display').show();
        } 

        return false;

    }

    function handle_mnemonic_confirm(inp) {

        var mnemonic_text = inp.val();
        var words = mnemonic_text.split(' ');
        if (words.length != 12) {
            $('body').removeClass('mnemonic-created-and-confirmed');
            return false;
        }

        var mne = new Mnemonic(words); 
        var seed = mne.toHex();
        if (seed == 'ffffffffffffffffffffffffffffffff') {
            $('body').removeClass('mnemonic-created-and-confirmed');
            return false;
        }

        var k = load_stored_key(seed) || key_for_new_seed(seed);
        k['user_confirmed_ts'] = new Date().getTime();

        if (!store_key(k, true)) {
            return false;
        }

        $('body').addClass('mnemonic-created-and-confirmed');
        $('#public-key').text(k['pub']);
        $('.public-key-display').show();

    }

    function reflect_contract_added(c) {

        //bootbox.alert('Please pay:<br />'+c['address']); 

        var url = sharing_url(c, false);
        $('#section3').attr('name', url);

        populate_contract_and_append_to_display(c);
        display_single_contract(c);

    }

    function import_contracts(import_url) {
        var pubkey = $('#public-key').text();
        var url = $('#import-contract-url').val() + pubkey;
        $.ajax({
            url: url, 
            type: 'GET',
            dataType: 'text', 
            success: function(data) {
                var lines = data.split("\n");
                for (i=0; i<lines.length; i++) {
                    var l = lines[i];
                    if (l == '') {
                        continue;
                    }
                    var c = hash_to_contract('#' + l);
                    import_contract_if_required(c);
                }
            },
            error: function(data) {
                console.log("got error from load");
                console.log(data);
            }
        });
        return false;
    }

    function hash_to_contract(import_hash) {

        if (!/^#.*-.*-\d+-t?btc$/.test(import_hash)) {
            //console.log('import hash wrongly formatted, not even going to try to parse it');
            return null;
        }

        var url_parts = import_hash.split('#');

        var url_part = url_parts[1];
        var contract_data = url_part.split('-');

        // not an import
        if (contract_data.length != 4) {
            return false;
        }

        var yes_user_pubkey =  format_pubkey(contract_data[0]);
        var no_user_pubkey = format_pubkey(contract_data[1]);
        var fact_id = format_fact_id(contract_data[2]);
        var is_testnet = prefix_to_testnet_setting(contract_data[3]);

        if ( yes_user_pubkey == null || no_user_pubkey == null || fact_id == null) {
            return null;
        }

        var c = {};
        c['yes_user_pubkey'] = yes_user_pubkey;
        c['no_user_pubkey'] = no_user_pubkey;
        c['id'] = fact_id;
        c['is_testnet'] = is_testnet;

        return c;

    }

    function view_contract_if_in_hash(import_hash) {

        var c = hash_to_contract(import_hash);
        if (c == null) {
            return false;
        }

        var url = sharing_url(c, false);
        $('#section3').attr('name', url);

        // Should already be this, but changing it now seems to force the page to jump properly
        document.location.hash = '#'+url;

        display_single_contract(c);
        $(document).scrollTop( $("#section3").offset().top );

        return false;

    }

    function charity_display_for_pubkey(pubkey) {
        var txt = $('#charity-select').find('[value='+pubkey+']').text();
        if (txt == '') {
            return pubkey;
        }
        return txt;
    }

    // TODO: This ends up duplicating a lot with display_single_contract
    function import_contract_if_required(c) {

        var wins_on = wins_on_for_stored_keys(c);
        if (wins_on == 'None') {
            return false;
        }

        // Start populated with the data we have, fetch the rest
        data = c;

        // Make sure we have at least one of the keys
        url = oracle_api_base + '/fact/' + c['id'] + '/' + oracle_param_string;
        console.log("fetching reality keys data:");
        console.log(url);
        $.ajax({
            url: url, 
            type: 'GET',
            dataType: 'json', 
            success: function(data) {
                data['wins_on'] = wins_on;
                data['charity_display'] = charity_display_for_pubkey(c['no_user_pubkey']);
                data['yes_user_pubkey'] = c['yes_user_pubkey'];
                data['no_user_pubkey'] = c['no_user_pubkey'];
                data['is_testnet'] = c['is_testnet'];
                data['address'] = p2sh_address(data);

                if (is_contract_stored(data['address'])) {
                    return true;
                }

                store_contract(data);
                reflect_contract_added(data);
                $(document).scrollTop( $("#section3").offset().top );
            },
            error: function(data) {
                console.log("got error from fake");
                console.log(data);
            }
        });
        return false;

    }

    function wins_on_for_stored_keys(c) {
        if (c == null) {
            return false;
        }
        if (stored_priv_for_pub(c['yes_user_pubkey'])) {
            return 'Yes';
        } else if (stored_priv_for_pub(c['no_user_pubkey'])) {
            return 'No';
        }  
        return 'None'
    }

    // Return a nicely-formatted date, if the browser supports it
    // Otherwise just return which you sent us, which should by eg 2014-08-16
    function formatted_date(iso_date) {
        try {
            var dt = new Date(iso_date);
            var formatted = dt.toLocaleString('en-US', {weekday: "long", year: "numeric", month: "long", day: "numeric"});
            return formatted;
        } catch (e) { 
            return iso_date;
        }
    }

    function display_single_contract(c) {

        //$('body').removeClass('for-list').addClass('for-single');

        $('#goal-view-reality-key-link').attr('href', '#');
        $('#goal-view-reality-key-link-container').hide();
        $('#goal-view-balance').text('');
        $('#goal-view-balance-container').hide();

        // Show a loading section
        $('.view-goal-form-loading').show();
        $('.view-goal-form-title').hide();

        // Hide the form part until we load it
        $('.goal-view-section').find('.completed-form-control').css('visibility', 'hidden');

        // ...but show the overall section so we can see it loading
        $('.goal-view-section').css('visibility', 'visible');

        c['charity_display'] = charity_display_for_pubkey(c['no_user_pubkey']);

        var wins_on = wins_on_for_stored_keys(c);
        if (wins_on == 'Yes') {
            $('.goal-view-section').addClass('wins-on-yes').removeClass('wins-on-no').removeClass('wins-on-none');
        } else if (wins_on == 'No') {
            $('.goal-view-section').addClass('wins-on-no').removeClass('wins-on-yes').removeClass('wins-on-none');
        }  else {
            $('.goal-view-section').addClass('wins-on-none').removeClass('wins-on-yes').removeClass('wins-on-no');
        }


        $('#view-goal-cancel').unbind('click').click( function() {
            //$('body').removeClass('for-single').addClass('for-list');
            return true;
        });


        // Start populated with the data we have, fetch the rest
        data = c;

        // Make sure we have at least one of the keys
        url = oracle_api_base + '/fact/' + c['id'] + '/' + oracle_param_string;
        console.log("fetching reality keys data:");
        console.log(url);
        $.ajax({
            url: url, 
            type: 'GET',
            dataType: 'json', 
            success: function(data) {

                data['wins_on'] = wins_on;
                data['charity_display'] = charity_display_for_pubkey(c['no_user_pubkey']);
                data['yes_user_pubkey'] = c['yes_user_pubkey'];
                data['no_user_pubkey'] = c['no_user_pubkey'];
                data['is_testnet'] = c['is_testnet'];
                //display_contract(data);

                data['address'] = p2sh_address(data);
                $('#view-contract-payable-address').text(data['address']);

                /*
                $('#view-user').text(data['user']);
                $('#view-activity').text(data['activity']);
                $('#view-measurement').text(data['measurement']);
                $('#view-goal').text(data['goal']);
                $('#view-settlement_date').text(data['settlement_date']);
                $('#view-charity-display-name').text(data['charity_display']);
                $('#view-charity-public-key').text(data['no_user_pubkey']);
                $('#view-user-public-key').text(data['yes_user_pubkey']);
                */

                $('#goal-view-reality-key-link').attr('href', oracle_view_base + c['id']).show();
                $('#goal-view-reality-key-link-container').show();

                $('#view-goal-store').unbind('click').click( function() {
                    store_contract(data);
                    reflect_contract_added(data);
                });

                if (is_contract_stored(data['address'])) {
                    $('#view-goal-store').hide();
                } else {
                    $('#view-goal-store').show();
                }
                var txt = '@bymycoins I will complete ' + data['activity'] + ' ' + data['goal'] + 'm by ' + formatted_date(data['settlement_date']) + ' or pay ' + data['charity_display'];
                txt = txt + ' ' + sharing_url(data, true);
                $('#tweet-button').attr('href', 'http://twitter.com/home?status=' + encodeURIComponent(txt));

                var section_title = data['user'] + ' to complete ' + data['activity'] + ' ' + data['goal'] + 'm by ' + formatted_date(data['settlement_date']);
                section_title = section_title.charAt(0).toUpperCase()+section_title.substring(1); // capitalize first letter

                // Should already be visible but do it again in case something happened out of sequence
                $('.goal-view-section').css('visibility', 'visible');
                $('.goal-view-section').find('.completed-form-control').css('visibility', 'visible');

                // Hide the loading text 
                $('.view-goal-form-loading').hide();
                $('.view-goal-form-title').text(section_title);
                $('.view-goal-form-title').show();

                $('.goal-view-section').find('form').css('visibility', 'visible');

                var winner = data['winner'];
                var is_winner_decided = (winner != null);

                var i_won = (winner == wins_on);
                if (is_winner_decided) {
                    $('.goal-view-section').addClass('decided').removeClass('undecided');
                    if (i_won) {
                        $('.goal-view-section').addClass('i-won').removeClass('i-lost');
                    } else {
                        $('.goal-view-section').addClass('i-lost').removeClass('i-won');
                    }
                    if (data['winner_privkey']) {
                        $('.goal-view-section').addClass('key-ready').removeClass('key-not-ready');
                    } else {
                        $('.goal-view-section').addClass('key-not-ready').removeClass('key-ready');
                    }
                } else {
                    $('.goal-view-section').addClass('undecided').removeClass('decided');
                    $('.goal-view-section').removeClass('i-lost').removeClass('i-won');
                }

                $('#section3').addClass('populated');

                //$('#single-claim-button').unbind('click').text('Checking balance...');
                // Now we have the address, we can get the balance
                var url = c['is_testnet'] ? 'https://tbtc.blockr.io/api/v1/address/balance/'+data['address'] : 'https://btc.blockr.io/api/v1/address/balance/'+data['address'];
                url = url + '?confirmations=0';
                $.ajax({
                    url: url, 
                    type: 'GET',
                    dataType: 'json', 
                    success: function(tx_data) {
                        var balance = tx_data['data']['balance'];

                        var contract_text = {
                            'activity_verb': data['activity'], // $('#activity').find(':selected').attr('data-verb'),
                            'goal_text': data['goal'] + ' meters',
                            'settlement_date': data['settlement_date'],
                            'charity_display': data['charity_display'],
                            'user': data['user']
                        }
                        $('.view-contract-title-start').text(formatted_title_start(contract_text, true));
                        $('.view-contract-title-end').text(formatted_title_end(contract_text, true));

                        $('#goal-view-balance').text(balance);
                        $('#goal-view-balance-container').show();
                        if (balance > 0 && i_won && data['winner_privkey']) {
                            $('#single-claim-button').unbind('click').click( function() {
                                var url = c['is_testnet'] ? 'https://tbtc.blockr.io/api/v1/address/unspent/'+data['address'] : 'https://btc.blockr.io/api/v1/address/unspent/'+data['address'];
                                url = url + '?confirmations=0';
                                url = url + '&unconfirmed=1'; // unspent seems to need both of these
                                console.log("fetching unspent:");
                                $.ajax({
                                    url: url, 
                                    type: 'GET',
                                    dataType: 'json', 
                                    success: function(tx_data) {
                                        var txes = tx_data['data']['unspent'];
                                        bootbox.prompt( 'What address to do want to send your winnings to?', function(result) {
                                            if (result !== null) {
                                                execute_claim(result, c, txes, data['winner_privkey']);
                                                return;
                                            }
                                            return;
                                        });
                                    },
                                    error: function(data) {
                                        console.log("got error from unspent");
                                        console.log(data);
                                    }
                                });
                            });
                            console.log("removing disabled");
                            $('#single-claim-button').prop('disabled',false);
                        } 
                        return;
                    },
                    error: function(data) {
                        console.log("got error from fake");
                        console.log(data);
                    }
                });
            },
            error: function(data) {
                console.log("got error");
                console.log(data);
            }
        });
        return false;

    }

    function eligius_cross_domain_post(data) {

        var url = 'http://eligius.st/~wizkid057/newstats/pushtxn.php';

        var iframe = document.createElement("iframe");
        document.body.appendChild(iframe);
        iframe.style.display = "none";

        // Just needs a unique name, last 16 characters of tx hex should be ok
        var target_name = 'tx-' + data.substring(data.length-16, data.length); 
        iframe.contentWindow.name = target_name;

        // construct a form with hidden inputs, targeting the iframe
        var form = document.createElement("form");
        form.target = target_name;
        form.action = url;
        form.method = "POST";

        var tx_input = document.createElement("input");
        tx_input.type = "hidden";
        tx_input.name = 'transaction';
        tx_input.value = data
        form.appendChild(tx_input);

        var send_input = document.createElement("input");
        send_input.type = "hidden";
        send_input.name = 'send';
        send_input.value = 'Push' 
        form.appendChild(send_input);

        document.body.appendChild(form);
        form.submit();

    }

    function execute_claim(to_addr, c, txes, winner_privkey) {

        var i;
        //console.log("executing claim");
        //console.log(c);

        //console.log("trying to find priv for ");
        //console.log(c['yes_user_pubkey']);
        var user_privkey = stored_priv_for_pub(c['yes_user_pubkey']);
        if (user_privkey == null) {
            user_privkey = stored_priv_for_pub(c['no_user_pubkey']);
        }
        if (user_privkey == null) {
            return false;
        }

        // TODO: This creates an outgoing transaction for each incoming transaction.
        // We should really make one single transaction for all of them.
        for (i=0; i < txes.length; i++) {
            
            var txHex = hex_for_claim_execution(to_addr, user_privkey, winner_privkey, txes[i], c); 
console.log(txHex);

            // For now our spending transaction is non-standard, so we have to send to eligius.
            // Hopefully this will be fixed in bitcoin core fairly soon, and we can use same the blockr code for testnet.
            // Presumably they do not support CORS, and we have to submit to their web form.
            // We will send our data by putting it in an iframe and submitting it.
            // We will not be able to read the result from the script, although we could make it visible to the user.
            if (!c['is_testnet']) {
                eligius_cross_domain_post(txHex);
            } else {
                // this will always be testnet until the happy day when bitcore makes our transactions standard
                var url = c['is_testnet'] ? 'https://tbtc.blockr.io/api/v1/tx/push' : 'https://btc.blockr.io/api/v1/tx/push';
                $.ajax({
                    type: "POST",
                    url: url,
                    data: {'hex': txHex },
                    success: function( response ) {
                        var txid = response['data'];
                        console.log(response);
                        c['claim_txid'] = txid;
                        store_contract(c, true);
                    },
                    error: function ( response ) {
                        bootbox.alert('Sending transaction failed.');
                        console.log(response);
                    },
                    dataType: 'json', 
                });
            }
        }
    }


    function hex_for_claim_execution(to_addr, priv1, priv2, tx, c) {
        var tx = tx_for_claim_execution(to_addr, priv1, priv2, tx, c); 
        var txHex =  tx.serialize().toString('hex');
        //console.log(txHex);

        return txHex;


    }

    function tx_for_claim_execution(to_addr, priv1, priv2, tx, c) {

        var network = c['is_testnet'] ? bitcore.networks['testnet'] : bitcore.networks['livenet'];

        //console.log(tx);
        var n = tx['n'];
        var txid = tx['tx'];
        var amount = tx['amount'];
        //console.log(tx);

        //alert('Next step: make tx for '+n+','+txid+','+amount);
        var utxos2 = [
        {
            address: c['address'],
            txid: tx['tx'],
            vout: tx['n'],
            ts: 1396375187,
            scriptPubKey: tx['script'],
            amount: amount,
            confirmations: 1
        }
        ];

        var pubkeys = [
            [ c['yes_user_pubkey'], c['yes_pubkey'] ],
            [ c['no_user_pubkey'], c['no_pubkey'] ],
            [ c['yes_user_pubkey'], c['no_user_pubkey'] ]
        ];
        //console.log(pubkeys);

        var opts = {network: network, nreq:[2,2,2], pubkeys:pubkeys};
        var fee = 10000 / 100000000;


        outs = [{address:to_addr, amount:(amount-fee)}];
        //console.log("outs:");
        //console.log(outs);

        var hashMap = {};
        hashMap[ c['address'] ] = redeem_script(c);

        //var privs = [winner_privkey, 'HERE'];
        //var privs = [winner_privkey];
        //console.log(winner_privkey);

        var b = new bitcore.TransactionBuilder(opts);
        b.setUnspent(utxos2);
        b.setHashToScriptMap(hashMap);
        b.setOutputs(outs);

        //console.log("user_privkey:");
        //console.log(user_privkey);

        //console.log("winner_privkey:");
        //console.log(winner_privkey);

        var user_wk = new bitcore.WalletKey({ network: network });
        user_wk.fromObj( {
            priv: priv1,
        });
        var user_wk_obj = user_wk.storeObj();
        var user_privkey_wif = user_wk_obj.priv;

        var winner_wk = new bitcore.WalletKey({ network: network });
        winner_wk.fromObj( {
            priv: priv2,
        });
        var winner_wk_obj = winner_wk.storeObj();
        var winner_privkey_wif = winner_wk_obj.priv;

        b.sign([user_privkey_wif, winner_privkey_wif]);
        //b.sign([winner_privkey, winner_privkey]);
        tx = b.build();
        return tx;
    }

    function testnet_setting_to_prefix(is_testnet) {
        if (is_testnet) {
            return 'tbtc';
        } else {
            return 'btc';
        }
    }

    function prefix_to_testnet_setting(prefix) {
        return (prefix == 'tbtc');
    }

    function sharing_url(c, full) {
        var store = c['yes_user_pubkey']+'-'+c['no_user_pubkey']+'-'+c['id']+'-'+testnet_setting_to_prefix(c['is_testnet']);;
        var base = '';
        if (full) {
            base += document.URL;
            base = base.replace(/\?.*$/, "");
            base = document.URL.replace(/\#.*$/, "");
            base += '#';
        }
        return base + store;
    }

    function append_contract_to_display(c) {


        var frm = $('#claim-form');

        // The address should uniquely identify the contract, so only ever add the same address once.
        if (frm.find( "[data-address='" + c['address'] + "']").length) {
            return;
        }

        var row = frm.find('.contract-data-template').clone().removeClass('contract-data-template').addClass('contract-data-row').attr('data-address',c['address']);

        row.find('.fund-button').unbind('click').click( function() {
            bootbox.alert('Please pay<br />'+c['address']);
            return false;
        });

        var txt = '@bymycoins I will complete ' + c['activity'] + ' ' + c['goal'] + 'm by ' + formatted_date(c['settlement_date']) + ' or pay ' + c['charity_display'];
        txt = txt + ' ' + sharing_url(c, true);
        row.find('.tweet-button').attr('href', 'http://twitter.com/home?status=' + encodeURIComponent(txt));

        var wins_on = wins_on_for_stored_keys(c);
        var winner = c['winner'];
        var is_winner_decided = (winner != null);

        var i_won = (winner == wins_on);
        if (is_winner_decided) {
            row.addClass('decided').removeClass('undecided');
            if (i_won) {
                row.addClass('i-won').removeClass('i-lost');
            } else {
                row.addClass('i-lost').removeClass('i-won');
            }
            if (data['winner_privkey']) {
                row.addClass('key-ready').removeClass('key-not-ready');
            } else {
                row.addClass('key-not-ready').removeClass('key-ready');
            }
        } else {
            row.addClass('undecided').removeClass('decided');
            row.removeClass('i-lost').removeClass('i-won');
        }

        if (wins_on == 'Yes') {
            row.addClass('wins-on-yes');
        } else if (wins_on == 'No') {
            row.addClass('wins-on-no');
        }

        var lnk = $('<a>');
        if (c['is_testnet']) {
            lnk.attr('href', 'https://tbtc.blockr.io/address/info/' + format_address(c['address']));
        } else {
            lnk.attr('href', 'https://blockchain.info/address/' + format_address(c['address']));
        }
        lnk.text(c['balance']);

        row.find( "[data-type='funds']" ).html(lnk);
        row.find( "[data-type='user']" ).text(c['user']);
        row.find( "[data-type='activity']" ).text(c['activity']);
        row.find( "[data-type='measurement']" ).text(c['measurement']);
        row.find( "[data-type='goal']" ).text(c['goal']);
        row.find( "[data-type='settlement_date']" ).text(c['settlement_date']);

        var charity_display = c['charity_display'];
        if (charity_display == '') {
            charity_display = c['no_user_pubkey'];
        }
        row.find( "[data-type='charity-display']" ).text(charity_display);

        if (c['balance'] > 0) {
            row.addClass('funded');
            row.find('.claim-button').click( function() {
                //alert('claiming');
                fact_id = c['id'];
                url = oracle_api_base + '/fact/' + fact_id + '/' + oracle_param_string;
                $.ajax({
                    url: url, 
                    type: 'GET',
                    dataType: 'json', 
                    success: function(data) {
                        if (!data.winner) {
                            alert('Sorry, winner not announced yet');
                            return;
                        }

                        var winner = data['winner'];
                        


                        if (data.winner == 'Yes') {
                            var winner_privkey_wif = data['winner_privkey'];
                            if (winner_privkey_wif == null) {
                                alert('Sorry, the key has not been published yet. Please try again soon.');
                            }
                            // This will be in WIF format for bitcoin livenet.
                            // We'll turn this into a network-neutral hex private key.
                            var w = new bitcore.WalletKey({
                                network: bitcore.networks.livenet,
                            });
                            w.fromObj({ priv: winner_privkey_wif });
                            var winner_privkey = w.privKey.private.toString('hex');
                           console.log(c); 
                            var url = c['is_testnet'] ? 'https://tbtc.blockr.io/api/v1/address/unspent/'+addr : 'https://btc.blockr.io/api/v1/address/unspent/'+addr;
                            url = url + '?confirmations=0';
                            url = url + '&unconfirmed=1'; // unspent seems to need both of these
                            $.ajax({
                                url: url, 
                                type: 'GET',
                                dataType: 'json', 
                                success: function(tx_data) {
                                    var txes = tx_data['data']['unspent'];
                                    bootbox.prompt( 'What address to do want to send your winnings to?', function(result) {
                                        if (result === null) {
                                            console.log("no result");
                                            return;
                                        }
                                        console.log("executing for "+result);
                                        //execute_claim(result, c, txes, winner_privkey);
                                        return;
                                    });
                                    return;
                                },
                                error: function(data) {
                                    console.log("got error from fake");
                                    console.log(data);
                                }
                            });
                            return;
                        } else {
                            alert('Sorry, you lost');
                            return;
                        }

                        alert('ok');
                    },
                    error: function(data) {
                        console.log("got error from fake");
                        console.log(data);
                    }
                });

                /*
                alert('claiming 2');
                */
                return false;
            });
        
        }

        row.insertAfter('.contract-data-template:last');
        row.show();

    }

    function display_contracts() {

        var contract_json_str = localStorage.getItem('contract_store');
        if (contract_json_str) {
            var contract_store = JSON.parse(contract_json_str);
            for (addr in contract_store['contracts']) {
                c = contract_store['contracts'][addr];
                c = populate_contract_and_append_to_display(c);
            }
        }

    }

    function populate_contract_and_append_to_display(c) {

        // Get the status from blockchain and reality keys
        var addr = c['address'];
        if (!addr) {
            return false;
        }

        var url = c.is_testnet ? 'https://tbtc.blockr.io/api/v1/address/balance/' + addr+'?confirmations=0' : 'https://btc.blockr.io/api/v1/address/balance/' + addr+'?confirmations=0';
        $.ajax({
            url: url, 
            type: 'GET',
            dataType: 'json', 
            success: function(data) {
                //console.log("got response from blockchain");
                //console.log(data);
                c['balance'] = data['data']['balance'];
                append_contract_to_display(c);
            },
            error: function(data) {
                console.log("got error from blockchain");
                console.log(data);
            }
        });

    }

    function key_for_new_seed(seed) {

        var privateKey = bitcore.util.sha256(seed);

        var key = new bitcore.Key();
        key.private = privateKey;
        key.regenerateSync();
        var hash = bitcore.util.sha256ripe160(key.public);

        return {
            'seed': seed,
            'version': '1.0',
            'priv': key.private.toString('hex'),
            'pub': key.public.toString('hex'),
            'user_confirmed_ts': null
        };

    }

    function p2sh_address(data, include_user_keys) {

        if (include_user_keys == null) {
            include_user_keys = true;
        }

        var script = redeem_script(data);
        address_version = data['is_testnet'] ? 'testnet' : 'livenet';
        var addr = bitcore.Address.fromScript(script, address_version);
        return addr.toString();

    }

    function redeem_script(data) {

        include_user_keys = true;

        var yes_pubkeys = [ data['yes_user_pubkey'], data['yes_pubkey'] ];
        var no_pubkeys = [ data['no_user_pubkey'], data['no_pubkey'] ];
        var user_pubkeys = [ data['yes_user_pubkey'], data['no_user_pubkey'] ];

        // multisig group p2sh
        var opts = {
            nreq: include_user_keys ? [2,2,2] : [2,2],
            pubkeys: include_user_keys ? [ yes_pubkeys, no_pubkeys, user_pubkeys ] : [ yes_pubkeys, no_pubkeys ]
        };

        var address_version = data['is_testnet'] ? 'testnet' : 'livenet';
        var info = TransactionBuilder.infoForP2sh(opts, address_version);
        var p2shScript = info.scriptBufHex;
        //console.log("redeem script:");
        //console.log(p2shScript);
        return p2shScript;

    }

    function update_submittable() {
        var ok = true;
        var profile = $('#user').val();
        if ( (profile == '') || ( $('#user').attr('data-validated-user') != profile) ) {
            ok = false;
        }
        if (ok) {
            //$('#set-goal-submit').removeAttr('disabled');
            $('body').addClass('athlete-connected');
        } else {
            //$('#set-goal-submit').attr('disabled', 'disabled');
            $('body').removeClass('athlete-connected');
        }
        return true;
    }

    // Check the user is authenticated so Reality Keys can get at their data.
    // Once they are, set their username in the data-validated-user attribute.
    function validate_user( inpjq ) {
        var profile = inpjq.val();
        if ( (profile != '') && (inpjq.attr('data-validated-user') != profile ) ) {
            var url = oracle_api_base + '/runkeeper/is-user-authenticated/' + profile;
            $.ajax({
                url: url, 
                type: 'GET',
                dataType: 'json', 
                success: function(data) {
                    if (data[profile]) {
                        inpjq.attr('data-validated-user', profile);
                    }
                    update_submittable();
                },
                error: function(data) {
                    update_submittable();
                }
            });
        } else {
            update_submittable();
        }
    }

    function url_parameter_by_name(name) {
        var match = RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
        return match && decodeURIComponent(match[1].replace(/\+/g, ' '));
    }

    function use_case_toggle(use_case) {
        if (use_case == 'individual') {
            $('.connect-section').show();
            $('.goal-section').show();
            $('.charity-only').hide();
            $('.individual-only').show();
            $(this).addClass('active');
            $('#page-charity-switch').removeClass('active');
        }
        if (use_case == 'charity') {
            $('.connect-section').hide();
            $('.goal-section').hide();
            $('.charity-only').show();
            $('.individual-only').hide();
            $(this).addClass('active');
            $('#page-individual-switch').removeClass('active');
        }
    }

    function select_to_icon(icon_class, attribute_name, selected_item) {
        $('.'+icon_class+':not([data-activity='+selected_item+'])').removeClass('selected');
        $('.'+icon_class+'[data-activity='+selected_item+']').addClass('selected');
    }

    function update_goal_text(frm) {
        frm.find('.activity-verb').text( $('#activity').find(':selected').attr('data-verb') );
        frm.find('.goal-text').text( $('#goal').val() + ' meters' );
        frm.find('.settlement-date-text').text( formatted_date($('#settlement_date').val()) );
        frm.find('.charity-display-text').text( $('#charity-select').find(':selected').text() );
        var user = $('#user').val();
        var user_text = ( user == '' ) ? '' : ', '+user+',';
        frm.find('.user-text').text( user_text );
        var contract_text = {
            'activity_verb': $('#activity').find(':selected').attr('data-verb'),
            'goal_text': $('#goal').val() + ' meters',
            'settlement_date': $('#settlement_date').val(),
            'charity_display': $('#charity-select').find(':selected').text(),
            'user': $('#user').val()
        }
        $('.contract-title-start').text(formatted_title_start(contract_text, false));
        $('.contract-title-end').text(formatted_title_end(contract_text, false));
    }

    function formatted_title_start(ct, past) {
        if (past) {
            txt = ct['user'] + ' swore';
            if (ct['total_received']) {
                txt += ' by ' + ct['total_received'] + ' BTC';
            } 
            txt += ' to ' + ct['activity_verb'] + ' ' + ct['goal_text'] + ' by '+formatted_date(ct['settlement_date']);  
            txt = txt.charAt(0).toUpperCase()+txt.substring(1); // capitalize first letter
            return txt;
        }
        var txt = 'I';
        if (ct['user'] != '') {
            txt += ', '+ct['user'] + ',';
        }
        txt += ' swear by my coins to ' + ct['activity_verb'] + ' ' + ct['goal_text'] + ' by '+formatted_date(ct['settlement_date']);  
        return txt;
    }

    function formatted_title_end(ct, past) {
        return '...or they will go to ' + ct['charity_display'];
    }

    function handle_set_goal_form_change() {
        update_goal_text($('#set-goal-form'));
        if ( $('#user').val() == '') {
            $('#set-goal-form').addClass('need-connect');
        } else {
            $('#set-goal-form').removeClass('need-connect');
        }
    }

    function register_contract() {

        var url = oracle_api_base + '/runkeeper/new';
        params = {
            'user': $('#user').val(),
            'activity': $('#activity').val(),
            'measurement': $('#measurement').val(),
            'goal': $('#goal').val(),
            'settlement_date': $('#settlement_date').val(),
            'comparison': 'ge',
            'objection_period_secs': (24*60*60),
            'accept_terms_of_service': 'current',
        };
        var wins_on = 'Yes';
        var user_pubkey = $('#public-key').text();
        var is_testnet = $('#is-testnet').is(':checked');
        var charity_display = $('#charity-select').find(':selected').text();
        var charity_pubkey = $('#charity-select').val();
        if (charity_pubkey == 'other') {
            charity_pubkey = $('#charity-public-key').val();
            charity_display = '';
        }
        if ( (user_pubkey == '') || (charity_pubkey == '') ) {
            console.log('missing a pubkey');
            return false;
        }
        // debugging thing to use an existing fact instead
        var response;
        var override_with_fact_id = parseInt($('#override-with-existing-fact-id').val());
        if (override_with_fact_id > 0) {
            var fact_id = 
            url = oracle_api_base + '/runkeeper/'+override_with_fact_id+'/'+oracle_param_string
            var response = $.ajax({
                url: url, 
                async: false,
                type: 'GET',
                dataType: 'json', 
            });
        } else {
            var response = $.ajax({
                url: url, 
                async: false,
                type: 'POST',
                data: params,
                dataType: 'json', 
            });
        }
        if (response.status != 200) {
            console.log(response);
            console.log(response.responseJSON['errors']);
            bootbox.alert('Sorry, could not register the fact with Reality Keys.');
            return false;
        }
        var data = response.responseJSON;
        data['wins_on'] = wins_on;
        data['yes_user_pubkey'] = user_pubkey;
        data['no_user_pubkey'] = charity_pubkey;
        data['charity_display'] = charity_display;
        data['is_testnet'] = is_testnet;
        data['address'] = p2sh_address(data);

        var jump_to = '#' + sharing_url(data, false);

        store_contract(data);
        reflect_contract_added(data);

        console.log("submitted, resulting data is:");
        console.log(data);
        document.location.hash = jump_to;
        $(document).scrollTop( $("#section3").offset().top );
        console.log(", resulting data is:");
        console.log(data);
        return false;

    }

    function initialize_page() {

        // Default the settlement date to 1 week from today
        var dt = new Date();
        dt.setDate(dt.getDate() + 7);
        var default_settlement_date = dt.toISOString().slice(0, 10);
        $('#settlement_date').val(default_settlement_date);

        $('#set-goal-form').change( function() {
            handle_set_goal_form_change();   
        });

        var athlete = url_parameter_by_name('completed_profile');
        if (athlete) {
            store_athlete(athlete);
            $('#user').val(athlete);
            handle_set_goal_form_change();   
        }


        select_to_icon('activity-icon', 'data-activity', $('#activity').val());
        $('.activity-icon').click( function() {
            var selected_val = $(this).attr('data-activity');
            $('#activity').val( selected_val );
            select_to_icon('activity-icon', 'data-activity', selected_val);
            handle_set_goal_form_change();   
        } );
        $('.charity-icon').click( function() {
            $('#charity-select').val( $(this).attr('data-charity') );
            if ($('#charity-select').val() == 'other') {
                $('#charity-public-key').show();
            } else {
                $('#charity-public-key').hide();
            }


            handle_set_goal_form_change();   
        } );

        var default_athlete = load_default_athlete();
        if (default_athlete != null) {
            $('body').addClass('athlete-connected');
            $('#user').val(default_athlete);
            handle_set_goal_form_change();   
        } 
        validate_user( $('#user') );

        $('#settlement_date').datepicker(
            {"dateFormat": 'yy-mm-dd' }
        );

        //console.log("trying to load default key");
        if (default_seed = load_default_key()) {
            //console.log("got default seed:");
            //console.log(default_seed);
            $('#mnemonic').val(seed_to_mnemonic(default_seed['seed']).toWords().join(' '));
            $('#is-testnet').prop('checked', default_seed['is_testnet']);
            $('#public-key').text(default_seed['pub']);
            $('.public-key-display').show();
        }

        if ($('#mnemonic').val() == '') {
            var mne = new Mnemonic(128);
            $('#mnemonic').val(mne.toWords().join(' '));
        }

        $('#mnemonic').change( function() {
            handle_mnemonic_change($('#mnemonic'));
        });
        $('#is-testnet').change( function() {
            handle_mnemonic_change($('#mnemonic'));
        });

        $('#confirm-mnemonic-button').unbind('click').click( function() {
            handle_mnemonic_confirm($('#mnemonic'));
            if ($(this).hasClass('do-set-goal-submit')) {
                register_contract();
                $(this).removeClass('do-set-goal-submit');
            }
            return false;
        });

        // Always run the change handler on init.
        // This will toggle the body class to show if we're ready to do other stuff
        handle_mnemonic_change($('#mnemonic'));

        if ($('#charity-select').val() != 'other') {
            $('#charity-public-key').hide();
        } 

        $('#charity-select').change( function() {
            if ($(this).val() == 'other') {
                $('#charity-public-key').show();
            } else {
                $('#charity-public-key').hide();
            }
        });

        $('#user').change( function() {
            validate_user( $(this) );
        });

        $('#authenticate-runkeeper-user').click( function() {
            var return_url = location.protocol + '//' + location.host + location.pathname;
            var url = oracle_base + '/runkeeper/start-auth/' + '?return_url=' + encodeURI(return_url);
            $(this).attr('href', url);
            return true;
        });

        update_goal_text($('#set-goal-form'));

        $('#set-goal-submit').click( function() {
            register_contract();
        });

        $('.jump-to-secret').click( function() {
            // Mark the button on the secret screen so we know to submit the form after doing the mnemonic confirmation
            $('#confirm-mnemonic-button').addClass('do-set-goal-submit');
            return true;
        });

        $('#claim-form').find('.contract-data-template').hide();
        update_submittable();

        display_contracts();

        $('.load-button').click( function() {
            return import_contracts( $('#import-contract-url').val() );
        });

        $('#page-individual-switch').click( function() {
            $('body').addClass('for-individuals').removeClass('for-charities');
            use_case_toggle('individual');
            $(this).addClass('active');
            $('#page-charity-switch').removeClass('active');
        });
        $('#page-charity-switch').click( function() {
            $('body').addClass('for-charities').removeClass('for-individuals');
            use_case_toggle('charity');
            $(this).addClass('active');
            $('#page-individual-switch').removeClass('active');
        });

        use_case_toggle('individual');

        // If there's a hash with the contract details, go straight to that contract
        if (document.location.hash) {
            if (document.location.hash == '#charity') {
                $('body').addClass('for-charities').removeClass('for-individuals');
                use_case_toggle('charity');
                $('#page-individual-switch').removeClass('active');
                $('#page-charity-switch').removeClass('active');
            } else {
                view_contract_if_in_hash(document.location.hash);
            }
        }

    }


