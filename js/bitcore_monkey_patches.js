var bitcore = require('bitcore');


bitcore = typeof (bitcore) === 'undefined' ? require('../bitcore') : bitcore;
var networks = bitcore.networks;
var WalletKey = bitcore.WalletKey;
var Script = bitcore.Script;
var TransactionBuilder = bitcore.TransactionBuilder;
var Buffer = bitcore.Buffer;
var Opcode = bitcore.Opcode;


Script._sortKeys = function(keys) {
    return keys;
}

Script.appendCheckMultiSigBits = function(script, n_required, inKeys, opts) {
    inKeys = opts.noSorting ? inKeys : this._sortKeys(inKeys);
    script.writeN(n_required);
    inKeys.forEach(function(key) {
        script.writeBytes(key);
    });
    script.writeN(inKeys.length);
    script.writeOp(Opcode.map.OP_CHECKMULTISIG);
    return script;
};

// Monkey-patch bitcoin-core Script TransactionBuilder to handle multiple sets of conditions.
// Script.createMultisig = function(n_required, inKeys, opts)... replaced by:
Script.createMultisigGroups = function( n_required_arr, inKeys_arr, opts) {

   var num_groups = n_required_arr.length;

    if (num_groups != inKeys_arr.length) {
        throw new Error("Number of sigs required must be supplied for each set of pubkeys, no more or less");
    }

    if (num_groups < 2) {
        throw new Error("Number of sigs is too low. If you only have one group, use a normal multisig transaction.");
    }

    if (num_groups > 3) {
        throw new Error("Number of groups is limited to 3");
    }

    /*
    We want a series of branches for each combination
    Patterns:
    2 groups
     OP_IF
     OP_ELSE
     OP_ENDIF

    3 groups
     OP_IF
        OP_IF
            group 1
        OP_ELSE
            group 2
        OP_ENDIF
     OP_ELSE
            group 3
     OP_ENDIF
    */

    // Flags that will be needed to solve the scripts for each group
    // We could generate this dynamically to accomodate infinite branches but they won't fit in the script anyhow...
    group_count_if_flags = {
        1: [ [] ],
        2: [
            [ 1 ], [ 0 ] 
           ],
        3: [ 
            [ 1, 1 ], [ 1, 0 ], [ 0 ] 
           ],
    };
    var flag_groups = group_count_if_flags[ num_groups ];

    opts = opts || {};

    var script = new Script();

    if (num_groups == 2) {
        script.writeOp( Opcode.map.OP_IF );
            script = Script.appendCheckMultiSigBits(script, n_required_arr[0], inKeys_arr[0], opts);
        script.writeOp( Opcode.map.OP_ELSE );
            script = Script.appendCheckMultiSigBits(script, n_required_arr[1], inKeys_arr[1], opts);
        script.writeOp( Opcode.map.OP_ENDIF);
    } else if (num_groups == 3) {
        script.writeOp( Opcode.map.OP_IF );
            script.writeOp( Opcode.map.OP_IF );
                script = Script.appendCheckMultiSigBits(script, n_required_arr[0], inKeys_arr[0], opts);
            script.writeOp( Opcode.map.OP_ELSE );
                script = Script.appendCheckMultiSigBits(script, n_required_arr[1], inKeys_arr[1], opts);
            script.writeOp( Opcode.map.OP_ENDIF);
        script.writeOp( Opcode.map.OP_ELSE );
                script = Script.appendCheckMultiSigBits(script, n_required_arr[2], inKeys_arr[2], opts);
        script.writeOp( Opcode.map.OP_ENDIF);
    }

    return script;

};


TransactionBuilder._signHashAndVerify = function(wk, txSigHash) {
  var triesLeft = 10, sigRaw;
  //console.log(".");
  //console.log(".");
  //console.log(".");
  //console.log("in _signHashAndVerify");
  //console.log(wk.privKey.private.toString('hex'));
  //console.log(wk);
  //console.log(txSigHash.toString('hex'));

  do {
    sigRaw = wk.privKey.signSync(txSigHash);
  } while (wk.privKey.verifySignatureSync(txSigHash, sigRaw) === false &&
           triesLeft--);

  if (triesLeft<0)
    throw new Error('could not sign input: verification failed');

  /*
  console.log("_signHashAndVerify returns:");
  console.log(sigRaw.toString('hex'));
  console.log(".");
  console.log(".");
  console.log(".");
  */
  return sigRaw;
};


/*
NB Unlike the original _signMultiSig this will only work if you pass in all the keys
This is because otherwise it doesn't know which ones actually need signing with.
*/
TransactionBuilder.prototype._signMultiSigGroups = function(walletKeyMap, input, txSigHash) {

    /*
    console.log("input:");
    console.log(input);

    console.log("TX Hash:");
    console.log(txSigHash.toString('hex'));

    console.log("Chunks:");
    console.log(input.scriptPubKey.chunks);
    */

    var section_pubs = [];
    var section_nreqs = [];
    
    var this_section = null;
    var section_nreq = null;

    // Keep a record of which pubkey is in which section.
    // That will allow us to work out which section we should try to sign.
    var pubkey_to_section = {}; 

    // Split the sections into [n pub pub pub m] sections
    // ...saving [pub, pub, pub] and n for each section
    for(var i=0; i<input.scriptPubKey.chunks.length; i++) {

        var this_chunk = input.scriptPubKey.chunks[i];

        // Any time we see a branching control character eg OP_IF or OP_ELSE
        // ...assume we're going to start a new section next
        // ...and close the previous one, if it's open

        if ( (this_chunk == Opcode.map.OP_IF) || (this_chunk == Opcode.map.OP_ELSE) || (this_chunk == Opcode.map.OP_ENDIF) ) {
            // If we have anything in the previous section, close it
            if (section_nreq > 0) {
                section_pubs.push(this_section);
                section_nreqs.push(section_nreq);
            }
            this_section = [];
            section_nreq = 0;
            continue;
        } 
        
        if ( (this_chunk == Opcode.map.OP_CHECKMULTISIG) || (this_chunk == Opcode.map.OP_CHECKMULTISIG) ) {
            continue;
        }

        if ( (this_chunk > (0 + 80)) && (this_chunk < (16 + 80) ) ) {
            if (section_nreq == 0) {
                section_nreq = (this_chunk - 80); 
            } 
            continue;
        }

        // Assume anything else is a pubkey...
        this_section.push(this_chunk);

    }

    /*
    console.log("wallet key map:");
    console.log(walletKeyMap);
    */

    // Work out which section to sign for
    signable_section = -1;
    for (var sec=0; sec < section_pubs.length; sec++) {
        if (signable_section > -1) {
            break;
        } 
        var pubs = section_pubs[sec];
        var nreq = section_nreqs[sec];
        var found = 0;
        for (var p=0; p < pubs.length; p++) {
            if (wk = this._findWalletKey(walletKeyMap, {pubKeyBuf: pubs[p]})) {
                found++;
                if (found == nreq) {
                    signable_section = sec; 
                    break;
                }
            } 
        }
    }
    //console.log("ended up with signable section "+signable_section);

    if (signable_section == -1) {
        console.log('not signable, give up');
        return false;
    }

    //var pubkeys = input.scriptPubKey.capture();
    //l = pubkeys.length;

    var nreq = section_nreqs[signable_section];
    var pubkeys = section_pubs[signable_section];

    originalScriptBuf = this.tx.ins[input.i].s;
    //console.log("originalScriptBuf:");
    //console.log(originalScriptBuf.toString('hex'));

    var scriptSig = new Script(originalScriptBuf);
    scriptSig.prependOp0(); // a nothing for checkmultisig to chomp on
    //console.log("initial sigscript");
    //console.log(scriptSig.toString('hex'));
    var signaturesAdded = 0;

    for(var j=0; j<pubkeys.length; j++) {
        var pub = pubkeys[j];
        //console.log("signing with pubkey:");
        //console.log(pub.toString('hex'));
        var wk = this._findWalletKey(walletKeyMap, {pubKeyBuf: pub});
        if (!wk) {
            //console.log("key not found, skipping");
            continue;
        }


        var sigRaw  = TransactionBuilder._signHashAndVerify(wk, txSigHash);
        var sigType = new Buffer(1);
        sigType[0]  = this.signhash;
        // console.log("sigtype is ");
        // console.log(sigType);
        var sig     = Buffer.concat([sigRaw, sigType]);
        // console.log("Made temp sig:");
        // console.log(sig.toString('hex'));

        scriptSig.chunks.push(sig);

        signaturesAdded++;
        if (signaturesAdded == nreq) {
            //console.log("done "+signaturesAdded+" sigs, break");
            break;
        }
    }

    //console.log("signable sectin:");


    // Support two-group and three-group patterns.
    // By convention we do the first two as inner if and the outer one as 
    if (section_nreqs.length == 2) {
        scriptSig.chunks.push( (signable_section == 0 ? Opcode.map.OP_1 : Opcode.map.OP_0) );
    } else if (section_nreqs.length == 3) {
        if (signable_section == 2) {
            scriptSig.chunks.push( Opcode.map.OP_0 ); // outer branch, there is no inner branch
        } else {
            scriptSig.chunks.push( Opcode.map.OP_1 ); // outer branch 1, then 1 for the first inner branch or 0 for the second
            scriptSig.chunks.push( (signable_section == 0 ? Opcode.map.OP_1 : Opcode.map.OP_0) );
        }
    }


    //alert(branch_flag);
    //console.log("chunks and buffer before branch flag:")
    //console.log(scriptSig.chunks);
    //console.log(scriptSig.getBuffer().length);
    scriptSig.updateBuffer();
    //console.log("chunks and buffer after branch flag:")
    //console.log(scriptSig.chunks);
    //console.log(scriptSig.getBuffer().length);

    var ret = {
        inputFullySigned: (signaturesAdded == nreq), // original version would have handled pre-signed transactions using countSignatures()
        signaturesAdded: signaturesAdded,
        script: scriptSig.getBuffer(),
    };
    //console.log("made ret:");
    //console.log(ret);
    return ret;

};

TransactionBuilder.prototype._signScriptHash = function(walletKeyMap, input, txSigHash) {
    var p2sh  = this._p2shInput(input);
    var ret   = fnToSign[p2sh.scriptType].call(this, walletKeyMap, p2sh.input, p2sh.txSigHash);
    if (ret && ret.script && ret.signaturesAdded) {
    ret.script = this._addScript(ret.script, p2sh.scriptBuf);
    }
    return ret;
};

Script.TX_TYPES = [
    'unknown',
    'pubkey',
    'pubkeyhash',
    'multisig',
    'scripthash',
    'multisig_groups'
]

Script.TX_MULTISIG_GROUPS = 5;

// This seems to be defined in global space in TransactionBuilder.
var fnToSign = {}; 
fnToSign[Script.TX_PUBKEYHASH] = TransactionBuilder.prototype._signPubKeyHash;
fnToSign[Script.TX_PUBKEY]     = TransactionBuilder.prototype._signPubKey;
fnToSign[Script.TX_MULTISIG]   = TransactionBuilder.prototype._signMultiSig;
fnToSign[Script.TX_SCRIPTHASH] = TransactionBuilder.prototype._signScriptHash;
fnToSign[Script.TX_MULTISIG_GROUPS] = TransactionBuilder.prototype._signMultiSigGroups;

Script.prototype.isMultiSigGroups = function() {
    // this will do for now, if we fell through to this test we'd get "unknown"
    // ...and nothing else would work anyhow
    return true;
};

//TransactionBuilder.fnToSign[TX_MULTISIG_GROUPS] = TransactionBuilder.prototype._signScriptHash;

// is this a script form we know?
Script.prototype.classify = function() {
    var ret = Script.TX_UNKNOWN;
    if (this.isPubkeyHash()) 
        ret = Script.TX_PUBKEYHASH;
    else if (this.isP2SH())
        ret = Script.TX_SCRIPTHASH;
    else if (this.isMultiSig())
        ret = Script.TX_MULTISIG;
    else if (this.isPubkey())
        ret = Script.TX_PUBKEY;
    else if (this.isMultiSigGroups())
        ret = Script.TX_MULTISIG_GROUPS;
    //console.log("classify is returning "+ret);
    return ret;
};

TransactionBuilder.prototype._p2shInput = function(input) {
    if (!this.hashToScriptMap)
        throw new Error('hashToScriptMap not set');

    var scriptHex = this.hashToScriptMap[input.address];
    if (!scriptHex) return;

    var scriptBuf     = new Buffer(scriptHex,'hex');
    var script        = new Script(scriptBuf);
    var scriptType    = script.classify();

    if (!fnToSign[scriptType] || scriptType === Script.TX_SCRIPTHASH)
        throw new Error('dont know how to sign p2sh script type:'+ script.getRawOutType());

    return {
        input: this._getInputForP2sh(script, input.i),
        txSigHash: this.tx.hashForSignature( script, input.i, this.signhash),
        scriptType: script.classify(),
        scriptBuf: scriptBuf,
    };
};

TransactionBuilder.prototype.sign = function(keys) {
    this._checkTx();
    var tx  = this.tx,
    ins = tx.ins,
    l   = ins.length,
    walletKeyMap = TransactionBuilder._mapKeys(keys);

    for (var i = 0; i < l; i++) {
        var input = this.inputMap[i];
        //console.log("fnToSign:");
        //console.log(fnToSign);

        var txSigHash = this.tx.hashForSignature(input.scriptPubKey, i, this.signhash);
        //console.log("scriptType is "+input.scriptType);
        //console.log("sign function is:");
        //console.log(fnToSign[input.scriptType]);
        var ret = fnToSign[input.scriptType].call(this, walletKeyMap, input, txSigHash);
        if (ret && ret.script) {
            tx.ins[i].s = ret.script;
            if (ret.inputFullySigned) this.inputsSigned++;
            if (ret.signaturesAdded) this.signaturesAdded +=ret.signaturesAdded;
        }
    }
    return this;
};

TransactionBuilder._scriptForPubkeysGroups = function(out) {
    // In a standard m of n out.nreq would be a an int for the required sig count
    // ...and out.pubkeys would be an array of pubkeys.
    // In the group version, out.nreq is an array of required sig counts 
    // ...and out.pubkeys is an array of arrays of pubkeys.
    gl = out.pubkeys.length;
    var pubKeyBufs=[];
    for (var j=0; j<gl; j++) {
        var l = out.pubkeys[j].length;
        var pubKeyBuf=[];
        for (var i=0; i<l; i++) {
            pubKeyBuf.push(new Buffer(out.pubkeys[j][i],'hex'));
        }
        pubKeyBufs.push(pubKeyBuf);
    }

    return Script.createMultisigGroups(out.nreq, pubKeyBufs);
};

// Override the original _scriptForOut to handle groups of requirements
TransactionBuilder._scriptForOut = function(out) {
    var ret;
    if (out.address)
        ret = this.scriptForAddress(out.address);
    else if (out.nreq && out.nreq instanceof Array) // if passed an array of needed m of n's, use the group version
        ret = this._scriptForPubkeysGroups(out);
    else if (out.pubkeys || out.nreq || out.nreq > 1) 
        ret = this._scriptForPubkeys(out);
    else
        throw new Error('unknown out type');

    return ret;
};
