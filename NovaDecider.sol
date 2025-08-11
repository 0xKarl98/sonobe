// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/*
    Sonobe's Nova + CycleFold decider verifier.
    Joint effort by 0xPARC & PSE.

    More details at https://github.com/privacy-scaling-explorations/sonobe
    Usage and design documentation at https://privacy-scaling-explorations.github.io/sonobe-docs/

    Uses the https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs
    Groth16 verifier implementation and a KZG10 Solidity template adapted from
    https://github.com/weijiekoh/libkzg.
    Additionally we implement the NovaDecider contract, which combines the
    Groth16 and KZG10 verifiers to verify the zkSNARK proofs coming from
    Nova+CycleFold folding.
*/


/* =============================== */
/* KZG10 verifier methods */
/**
 * @author  Privacy and Scaling Explorations team - pse.dev
 * @dev     Contains utility functions for ops in BN254; in G_1 mostly.
 * @notice  Forked from https://github.com/weijiekoh/libkzg.
 * Among others, a few of the changes we did on this fork were:
 * - Templating the pragma version
 * - Removing type wrappers and use uints instead
 * - Performing changes on arg types
 * - Update some of the `require` statements 
 * - Use the bn254 scalar field instead of checking for overflow on the babyjub prime
 * - In batch checking, we compute auxiliary polynomials and their commitments at the same time.
 */
contract KZG10Verifier {

    // prime of field F_p over which y^2 = x^3 + 3 is defined
    uint256 public constant BN254_PRIME_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /**
     * @notice  Performs scalar multiplication in G_1.
     * @param   p  G_1 point to multiply
     * @param   s  Scalar to multiply by
     * @return  r  G_1 point p multiplied by scalar s
     */
    function mulScalar(uint256[2] memory p, uint256 s) internal view returns (uint256[2] memory r) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success
            case 0 { invalid() }
        }
        require(success, "bn254: scalar mul failed");
    }

    /**
     * @notice  Negates a point in G_1.
     * @param   p  G_1 point to negate
     * @return  uint256[2]  G_1 point -p
     */
    function negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return p;
        }
        return [p[0], BN254_PRIME_FIELD - (p[1] % BN254_PRIME_FIELD)];
    }

    /**
     * @notice  Adds two points in G_1.
     * @param   p1  G_1 point 1
     * @param   p2  G_1 point 2
     * @return  r  G_1 point p1 + p2
     */
    function add(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory r) {
        bool success;
        uint256[4] memory input = [p1[0], p1[1], p2[0], p2[1]];
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: point add failed");
    }

    /**
     * @notice  Computes the pairing check e(p1, p2) * e(p3, p4) == 1
     * @dev     Note that G_2 points a*i + b are encoded as two elements of F_p, (a, b)
     * @param   a_1  G_1 point 1
     * @param   a_2  G_2 point 1
     * @param   b_1  G_1 point 2
     * @param   b_2  G_2 point 2
     * @return  result  true if pairing check is successful
     */
    function pairing(uint256[2] memory a_1, uint256[2][2] memory a_2, uint256[2] memory b_1, uint256[2][2] memory b_2)
        internal
        view
        returns (bool result)
    {
        uint256[12] memory input = [
            a_1[0],
            a_1[1],
            a_2[0][1], // imaginary part first
            a_2[0][0],
            a_2[1][1], // imaginary part first
            a_2[1][0],
            b_1[0],
            b_1[1],
            b_2[0][1], // imaginary part first
            b_2[0][0],
            b_2[1][1], // imaginary part first
            b_2[1][0]
        ];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 0x180, out, 0x20)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: pairing failed");

        return out[0] == 1;
    }

    uint256[2] G_1 = [
            11166542083255899381871195030173017950542071972977566228748192932121781406487,
            4675700218401402714383766663576911879767686345543007563209108278701687161756
    ];
    uint256[2][2] G_2 = [
        [
            20622258672087937788545408128215444154229668369364436802809030883711716420217,
            6307887526644106227307365029876614302256107388022715070312714871982066810583
        ],
        [
            17143987542377514788505971214642154470973580204309941749575528900158814645582,
            20406927381564580753534326672114798926354610470262769648401802981077370477142
        ]
    ];
    uint256[2][2] VK = [
        [
            20597248683270154424847837534377665937319179822909477143978510819313755766546,
            19338462315112266740538203968250456098509574455503130702277784833757727545276
        ],
        [
            6573255782346875013908255540779480794203615814861033691837364657650841226538,
            5052598633326651928627945160316347181363850676074638252445010307981899245882
        ]
    ];

    

    /**
     * @notice  Verifies a single point evaluation proof. Function name follows `ark-poly`.
     * @dev     To avoid ops in G_2, we slightly tweak how the verification is done.
     * @param   c  G_1 point commitment to polynomial.
     * @param   pi G_1 point proof.
     * @param   x  Value to prove evaluation of polynomial at.
     * @param   y  Evaluation poly(x).
     * @return  result Indicates if KZG proof is correct.
     */
    function check(uint256[2] calldata c, uint256[2] calldata pi, uint256 x, uint256 y)
        public
        view
        returns (bool result)
    {
        //
        // we want to:
        //      1. avoid gas intensive ops in G2
        //      2. format the pairing check in line with what the evm opcode expects.
        //
        // we can do this by tweaking the KZG check to be:
        //
        //          e(pi, vk - x * g2) = e(c - y * g1, g2) [initial check]
        //          e(pi, vk - x * g2) * e(c - y * g1, g2)^{-1} = 1
        //          e(pi, vk - x * g2) * e(-c + y * g1, g2) = 1 [bilinearity of pairing for all subsequent steps]
        //          e(pi, vk) * e(pi, -x * g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(-x * pi, g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(x * -pi - c + y * g1, g2) = 1 [done]
        //                        |_   rhs_pairing  _|
        //
        uint256[2] memory rhs_pairing =
            add(mulScalar(negate(pi), x), add(negate(c), mulScalar(G_1, y)));
        return pairing(pi, VK, rhs_pairing, G_2);
    }

    function evalPolyAt(uint256[] memory _coefficients, uint256 _index) public pure returns (uint256) {
        uint256 m = BN254_SCALAR_FIELD;
        uint256 result = 0;
        uint256 powerOfX = 1;

        for (uint256 i = 0; i < _coefficients.length; i++) {
            uint256 coeff = _coefficients[i];
            assembly {
                result := addmod(result, mulmod(powerOfX, coeff, m), m)
                powerOfX := mulmod(powerOfX, _index, m)
            }
        }
        return result;
    }

    
}

/* =============================== */
/* Groth16 verifier methods */
/*
    Copyright 2021 0KIMS association.

    * `solidity-verifiers` added comment
        This file is a template built out of [snarkJS](https://github.com/iden3/snarkjs) groth16 verifier.
        See the original ejs template [here](https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs)
    *

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 17847974448309854843459009960787993054607854657433993499335655300032038602488;
    uint256 constant alphay  = 6944243205155036337774380893784687549423241763881093401322749613105568891382;
    uint256 constant betax1  = 19988613271658944146672580462341401557212129990363153790957179952311397756510;
    uint256 constant betax2  = 10448077347918773299937582169532885913632511727261574604311969362294648029423;
    uint256 constant betay1  = 3803375836772936722596039659280614110313963102185955461246236996224290879952;
    uint256 constant betay2  = 5650162796024710848140987766397319496804531502869509122950911425449330644364;
    uint256 constant gammax1 = 17749915423116655975854202540948995820685841709883647368684664475536465908541;
    uint256 constant gammax2 = 6495256755588842835603204898505216334153908323843517597615792216157589569740;
    uint256 constant gammay1 = 5088902286286519864177618682865271947731624393940584926982943712859365796647;
    uint256 constant gammay2 = 12374400768927658941406906860628053428766724753720661069958879913788659119384;
    uint256 constant deltax1 = 1080736730989506271677937432966613314046759303656004930771020968429644030535;
    uint256 constant deltax2 = 21055131399145108709847912105200354063290171741655928274034575557172138018145;
    uint256 constant deltay1 = 6820780709096224125138351985239611699621557266364395511730233351686109064829;
    uint256 constant deltay2 = 4916717310768509735186511550970314008751691873277021210787725645795716954901;

    
    uint256 constant IC0x = 13635380489381680743487549901181025285280799508902421353134164673801652535996;
    uint256 constant IC0y = 17040276421333117881061938467409467706997975723683297829949941411324701422311;
    
    uint256 constant IC1x = 19307517857449199429570959982845083027608335740219792112610773742438328226348;
    uint256 constant IC1y = 4922412014181021867321040264342643274617671749356048070797453090405124335275;
    
    uint256 constant IC2x = 7253807871000220332901077358303767978007098828624740929337328825576781214844;
    uint256 constant IC2y = 13194211290218234784081315924757332003133766956549772870836521324720079154083;
    
    uint256 constant IC3x = 19790354069411364442347222091871905044259811783638469963817281610055900525812;
    uint256 constant IC3y = 15672839046413256094508347187138836142485011916973489275098318036584079185116;
    
    uint256 constant IC4x = 4137461137664727860584116127654504785622281359166347259477631428027200146491;
    uint256 constant IC4y = 13129305491816843419659886672802937625046311573783456303044350953447530009938;
    
    uint256 constant IC5x = 7512964398928031012365374489544365410431597129351771865637980978981069027701;
    uint256 constant IC5y = 18855391038814523031850209577085102672917542123785982853369266607189077104371;
    
    uint256 constant IC6x = 20717675905419529463123285814075455899702221185073339885985084153298984744261;
    uint256 constant IC6y = 6964983037072288540737618431555894198655978238675703448231674703453502905456;
    
    uint256 constant IC7x = 14032558743654078827495320462269445624847392239105655601464923334611535221416;
    uint256 constant IC7y = 83046744453051066158866710195938736171889358749586485060684342038759891727;
    
    uint256 constant IC8x = 7170296263662807657050527500074288542434175816633652043268838776960900320051;
    uint256 constant IC8y = 16998331353642291732529667195648326693907270404107264030985437543428690729166;
    
    uint256 constant IC9x = 15418747896700935294185403762537320467737920997137807515341789673201641663094;
    uint256 constant IC9y = 14739461353419778018099458147589170437643374670110156816479999693993759348288;
    
    uint256 constant IC10x = 274921107282505268470972866544890244888612603347211587669984306777113550397;
    uint256 constant IC10y = 19500290754673680762460078942956221559896505112122851367120533611210583630384;
    
    uint256 constant IC11x = 18188902546331106292254290375187740978191695843039201547003222838963772244585;
    uint256 constant IC11y = 2293624021352985067111821696359441718211930132727286705406909598156444665930;
    
    uint256 constant IC12x = 6455178412494685485725983480806041697954552204128937761866203770792395015171;
    uint256 constant IC12y = 10268159550767533431514692634556774822900970812008898005174267250296159197856;
    
    uint256 constant IC13x = 4629221778620632277941728170079029183301833094506670623949061914103992190552;
    uint256 constant IC13y = 19381910868793987056911718987454848969725273180323556653386959233403117491004;
    
    uint256 constant IC14x = 11956495441951541682670053994950252721306916102933536608059006540837052992282;
    uint256 constant IC14y = 14046581319630363417622906258475665067645197931113512519770030723229369438853;
    
    uint256 constant IC15x = 7019971750005369584248754013347511277298554047557371517901822968279751101162;
    uint256 constant IC15y = 16644270689571254335484932674270598507331970095483281861797841683845766196360;
    
    uint256 constant IC16x = 16723120022938037240249528353890301159674530566861209324875889259754712802239;
    uint256 constant IC16y = 6997466523701469790592575462728160319905806405903007753974419168859564348873;
    
    uint256 constant IC17x = 14584494889982262228798964785743047803658730584232400936799476566041177947656;
    uint256 constant IC17y = 2209407800302329125429845695633389792582854530271292753731966245168201433027;
    
    uint256 constant IC18x = 11823319295545405702519948454265728261963023551580454276124603673269928232915;
    uint256 constant IC18y = 16189132379831588997410764257032819803531104127110897340513127021012980054098;
    
    uint256 constant IC19x = 10144618935169150988788871226789390066926519961337080627461533907367289416304;
    uint256 constant IC19y = 20278696871160724395706974192231553596038879663956103918774534096913195317799;
    
    uint256 constant IC20x = 4474322989313355492972954781855627852994679768828778749899371074546145092300;
    uint256 constant IC20y = 20068905414514853101153508290247678362248060116338505313771667325068082783304;
    
    uint256 constant IC21x = 12980944201128757446972134622034636770526564051647985487878479368128025952873;
    uint256 constant IC21y = 16177817251420011479233454889477890130830684186963092254913765441747545716077;
    
    uint256 constant IC22x = 18875562988970459409084662101203136067018953560649220447774947764019948890158;
    uint256 constant IC22y = 13248192655227775803171698972840499440846986337092324747730146654483379835166;
    
    uint256 constant IC23x = 21056827152818934417344471856504369334708210999395824670379075686998710293151;
    uint256 constant IC23y = 16806917841499224788295349047240100705977626202695460350581430944496826467151;
    
    uint256 constant IC24x = 4024441095924338428923391817714949760287643558920178994094637569094521271174;
    uint256 constant IC24y = 8700630533049843234089107721825882726587993808200762419711005222562552882498;
    
    uint256 constant IC25x = 16104861825156693673659161589035190615103182139553100221079159982967244679048;
    uint256 constant IC25y = 20157974764459695441870007650491258701701153899546947014192900105774319193352;
    
    uint256 constant IC26x = 9501586879401167028659086786616056024483561475835454360855677834496395059595;
    uint256 constant IC26y = 18358843759348970874525653266402205616156466536887723155725338939991457509146;
    
    uint256 constant IC27x = 16715761325996748688931752704964746230286753247191486506966750436612087446290;
    uint256 constant IC27y = 16049582429809288876955125386506354252766159901338244893451235267509278659931;
    
    uint256 constant IC28x = 12354579782904519856910519942663707175603213757509547111943858646814705606703;
    uint256 constant IC28y = 5634261312638259258841395012944593129039132564966798549570089466880104677444;
    
    uint256 constant IC29x = 10819480956616608814093756739661003703930328221165059692917317734837627124596;
    uint256 constant IC29y = 6257858066968047699936256871490064739135366087970600133231309519873101044010;
    
    uint256 constant IC30x = 20601133022331629218025784816354691284359288353825490679914621124260196300808;
    uint256 constant IC30y = 19264678549568847903042148996803034385198711914534403405629180017138174358112;
    
    uint256 constant IC31x = 14199305784932344949599379055611036373095557973888600808896018816678526833528;
    uint256 constant IC31y = 6119799164654811930143488957869245209734749071916799776852156263166050850685;
    
    uint256 constant IC32x = 15543901166229324673174630378135535798933046880101669070581295277239307421395;
    uint256 constant IC32y = 3823481425155226230692028220887034815237395225739200621552942500148921248521;
    
    uint256 constant IC33x = 16499166517719992026790056131636332004056066143448711103351626906436589087437;
    uint256 constant IC33y = 4938553410183238798761189017722840358863710037696250059706477721507689980597;
    
    uint256 constant IC34x = 18806637733116211680256471862738773737416853821380110725462678583797890755943;
    uint256 constant IC34y = 13465277774780546455385339102979698359737407177232361775295470022008305892318;
    
    uint256 constant IC35x = 6356245040867550457785587141370763610163879427099866143362726429408170949681;
    uint256 constant IC35y = 1191731960247096719791451023654180434224137115464303128197494887440287090230;
    
    uint256 constant IC36x = 1838866193457625958403593712172640983323597391335811685670614145509183204586;
    uint256 constant IC36y = 7821729322724315423756002567427560686717617993170911118173644855964039631444;
    
    uint256 constant IC37x = 8376237860893792464017901512653913003769305457606021324617531641127466115783;
    uint256 constant IC37y = 20323511230805435302042370037796773729102295829665248578508195884990129884410;
    
    uint256 constant IC38x = 9670070691807674734504942290870740957189844490210958004191983181155345953152;
    uint256 constant IC38y = 20990901689305017458708919344654093501123533353989632413052689524189539976856;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[38] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            
            return(0, 0x20)
        }
    }
}


/* =============================== */
/* Nova+CycleFold Decider verifier */
/**
 * @notice  Computes the decomposition of a `uint256` into num_limbs limbs of bits_per_limb bits each.
 * @dev     Compatible with sonobe::folding-schemes::folding::circuits::nonnative::nonnative_field_to_field_elements.
 */
library LimbsDecomposition {
    function decompose(uint256 x) internal pure returns (uint256[5] memory) {
        uint256[5] memory limbs;
        for (uint8 i = 0; i < 5; i++) {
            limbs[i] = (x >> (55 * i)) & ((1 << 55) - 1);
        }
        return limbs;
    }
}

/**
 * @author PSE & 0xPARC
 * @title  Interface for the NovaDecider contract hiding proof details.
 * @dev    This interface enables calling the verifyNovaProof function without exposing the proof details.
 */
interface OpaqueDecider {
    /**
     * @notice  Verifies a Nova+CycleFold proof given initial and final IVC states, number of steps and the rest proof inputs concatenated.
     * @dev     This function should simply reorganize arguments and pass them to the proper verification function.
     */
    function verifyOpaqueNovaProofWithInputs(
        uint256 steps, // number of folded steps (i)
        uint256[1] calldata initial_state, // initial IVC state (z0)
        uint256[1] calldata final_state, // IVC state after i steps (zi)
        uint256[25] calldata proof // the rest of the decider inputs
    ) external view returns (bool);

    /**
     * @notice  Verifies a Nova+CycleFold proof given all the proof inputs collected in a single array.
     * @dev     This function should simply reorganize arguments and pass them to the proper verification function.
     */
    function verifyOpaqueNovaProof(uint256[28] calldata proof) external view returns (bool);
}

/**
 * @author  PSE & 0xPARC
 * @title   NovaDecider contract, for verifying Nova IVC SNARK proofs.
 * @dev     This is an askama template which, when templated, features a Groth16 and KZG10 verifiers from which this contract inherits.
 */
contract NovaDecider is Groth16Verifier, KZG10Verifier, OpaqueDecider {
    /**
     * @notice  Computes the linear combination of a and b with r as the coefficient.
     * @dev     All ops are done mod the BN254 scalar field prime
     */
    function rlc(uint256 a, uint256 r, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, mulmod(r, b, BN254_SCALAR_FIELD), BN254_SCALAR_FIELD)
        }
    }

    /**
     * @notice  Verifies a nova cyclefold proof consisting of two KZG proofs and of a groth16 proof.
     * @dev     The selector of this function is "dynamic", since it depends on `z_len`.
     */
    function verifyNovaProof(
        // inputs are grouped to prevent errors due stack too deep
        uint256[3] calldata i_z0_zi, // [i, z0, zi] where |z0| == |zi|
        uint256[4] calldata U_i_cmW_U_i_cmE, // [U_i_cmW[2], U_i_cmE[2]]
        uint256[2] calldata u_i_cmW, // [u_i_cmW[2]]
        uint256[3] calldata cmT_r, // [cmT[2], r]
        uint256[2] calldata pA, // groth16 
        uint256[2][2] calldata pB, // groth16
        uint256[2] calldata pC, // groth16
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, // [challenge_W, challenge_E, eval_W, eval_E]
        uint256[2][2] calldata kzg_proof // [proof_W, proof_E]
    ) public view returns (bool) {

        require(i_z0_zi[0] >= 2, "Folding: the number of folded steps should be at least 2");

        // from gamma_abc_len, we subtract 1. 
        uint256[38] memory public_inputs; 

        public_inputs[0] = 15583154179326249834107651564276154257263879926782187946023486356777829737600;
        public_inputs[1] = i_z0_zi[0];

        for (uint i = 0; i < 2; i++) {
            public_inputs[2 + i] = i_z0_zi[1 + i];
        }

        {
            // U_i.cmW + r * u_i.cmW
            uint256[2] memory mulScalarPoint = super.mulScalar([u_i_cmW[0], u_i_cmW[1]], cmT_r[2]);
            uint256[2] memory cmW = super.add([U_i_cmW_U_i_cmE[0], U_i_cmW_U_i_cmE[1]], mulScalarPoint);

            {
                uint256[5] memory cmW_x_limbs = LimbsDecomposition.decompose(cmW[0]);
                uint256[5] memory cmW_y_limbs = LimbsDecomposition.decompose(cmW[1]);
        
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[4 + k] = cmW_x_limbs[k];
                    public_inputs[9 + k] = cmW_y_limbs[k];
                }
            }
        
            require(this.check(cmW, kzg_proof[0], challenge_W_challenge_E_kzg_evals[0], challenge_W_challenge_E_kzg_evals[2]), "KZG: verifying proof for challenge W failed");
        }

        {
            // U_i.cmE + r * cmT
            uint256[2] memory mulScalarPoint = super.mulScalar([cmT_r[0], cmT_r[1]], cmT_r[2]);
            uint256[2] memory cmE = super.add([U_i_cmW_U_i_cmE[2], U_i_cmW_U_i_cmE[3]], mulScalarPoint);

            {
                uint256[5] memory cmE_x_limbs = LimbsDecomposition.decompose(cmE[0]);
                uint256[5] memory cmE_y_limbs = LimbsDecomposition.decompose(cmE[1]);
            
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[14 + k] = cmE_x_limbs[k];
                    public_inputs[19 + k] = cmE_y_limbs[k];
                }
            }

            require(this.check(cmE, kzg_proof[1], challenge_W_challenge_E_kzg_evals[1], challenge_W_challenge_E_kzg_evals[3]), "KZG: verifying proof for challenge E failed");
        }

        {
            // add challenges
            public_inputs[24] = challenge_W_challenge_E_kzg_evals[0];
            public_inputs[25] = challenge_W_challenge_E_kzg_evals[1];
            public_inputs[26] = challenge_W_challenge_E_kzg_evals[2];
            public_inputs[27] = challenge_W_challenge_E_kzg_evals[3];

            uint256[5] memory cmT_x_limbs;
            uint256[5] memory cmT_y_limbs;
        
            cmT_x_limbs = LimbsDecomposition.decompose(cmT_r[0]);
            cmT_y_limbs = LimbsDecomposition.decompose(cmT_r[1]);
        
            for (uint8 k = 0; k < 5; k++) {
                public_inputs[24 + 4 + k] = cmT_x_limbs[k]; 
                public_inputs[29 + 4 + k] = cmT_y_limbs[k];
            }

            bool success_g16 = this.verifyProof(pA, pB, pC, public_inputs);
            require(success_g16 == true, "Groth16: verifying proof failed");
        }

        return(true);
    }

    /**
     * @notice  Verifies a Nova+CycleFold proof given initial and final IVC states, number of steps and the rest proof inputs concatenated.
     * @dev     Simply reorganization of arguments and call to the `verifyNovaProof` function.
     */
    function verifyOpaqueNovaProofWithInputs(
        uint256 steps,
        uint256[1] calldata initial_state,
        uint256[1] calldata final_state,
        uint256[25] calldata proof
    ) public override view returns (bool) {
        uint256[1 + 2 * 1] memory i_z0_zi;
        i_z0_zi[0] = steps;
        for (uint256 i = 0; i < 1; i++) {
            i_z0_zi[i + 1] = initial_state[i];
            i_z0_zi[i + 1 + 1] = final_state[i];
        }

        uint256[4] memory U_i_cmW_U_i_cmE = [proof[0], proof[1], proof[2], proof[3]];
        uint256[2] memory u_i_cmW = [proof[4], proof[5]];
        uint256[3] memory cmT_r = [proof[6], proof[7], proof[8]];
        uint256[2] memory pA = [proof[9], proof[10]];
        uint256[2][2] memory pB = [[proof[11], proof[12]], [proof[13], proof[14]]];
        uint256[2] memory pC = [proof[15], proof[16]];
        uint256[4] memory challenge_W_challenge_E_kzg_evals = [proof[17], proof[18], proof[19], proof[20]];
        uint256[2][2] memory kzg_proof = [[proof[21], proof[22]], [proof[23], proof[24]]];

        return this.verifyNovaProof(
            i_z0_zi,
            U_i_cmW_U_i_cmE,
            u_i_cmW,
            cmT_r,
            pA,
            pB,
            pC,
            challenge_W_challenge_E_kzg_evals,
            kzg_proof
        );
    }

    /**
     * @notice  Verifies a Nova+CycleFold proof given all proof inputs concatenated.
     * @dev     Simply reorganization of arguments and call to the `verifyNovaProof` function.
     */
    function verifyOpaqueNovaProof(uint256[28] calldata proof) public override view returns (bool) {
        uint256[1] memory z0;
        uint256[1] memory zi;
        for (uint256 i = 0; i < 1; i++) {
            z0[i] = proof[i + 1];
            zi[i] = proof[i + 1 + 1];
        }

        uint256[25] memory extracted_proof;
        for (uint256 i = 0; i < 25; i++) {
            extracted_proof[i] = proof[3 + i];
        }

        return this.verifyOpaqueNovaProofWithInputs(proof[0], z0, zi, extracted_proof);
    }
}