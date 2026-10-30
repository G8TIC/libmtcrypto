/* aes_256_gcm_test.c -- NIST CAVP vectors and misuse/failure tests. SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_256_gcm.h"

static unsigned int checks;
static void check(int value, const char *label)
{
	++checks;
	if (!value) {
		fprintf(stderr, "FAIL: %s\n", label);
		exit(EXIT_FAILURE);
	}
}

static size_t decode(uint8_t *out, size_t capacity, const char *hex)
{
	size_t length = strlen(hex) / 2;

	check(strlen(hex) % 2 == 0 && length <= capacity, "hex fixture capacity");
	for (size_t i = 0; i < length; ++i) {
		unsigned int byte;

		if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
			check(0, "hex fixture syntax");
		}
		out[i] = (uint8_t)byte;
	}
	return length;
}

/* First case in each PTlen/AADlen group, IVlen=96, Taglen=96 or 128. */
/* NIST gcmEncryptExtIV256.rsp, CAVS 14.0, generated 2012-08-31. */
/* Source: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes */
static const struct {
	const char *key, *iv, *pt, *aad, *ct, *tag;
} vectors[] = {
	{
		"b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
		"516c33929df5a3284ff463d7",
		"",
		"",
		"",
		"bdc1ac884d332457a1d2664f168c76f0"
	},
	{
		"78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223",
		"d79cf22d504cc793c3fb6c8a",
		"",
		"b96baa8c1c75a671bfb2d08d06be5f36",
		"",
		"3e5d486aa2e30b22e040b85723a06e76"
	},
	{
		"886cff5f3e6b8d0e1ad0a38fcdb26de97e8acbe79f6bed66959a598fa5047d65",
		"3a8efa1cd74bbab5448f9945",
		"",
		"519fee519d25c7a304d6c6aa1897ee1eb8c59655",
		"",
		"f6d47505ec96c98a42dc3ae719877b87"
	},
	{
		"f4069bb739d07d0cafdcbc609ca01597f985c43db63bbaaa0debbb04d384e49c",
		"d25ff30fdc3d464fe173e805",
		"",
		"3e1449c4837f0892f9d55127c75c4b25d69be334baf5f19394d2d8bb460cbf21"
		"20e14736d0f634aa792feca20e455f11",
		"",
		"805ec2931c2181e5bfb74fa0a975f0cf"
	},
	{
		"03ccb7dbc7b8425465c2c3fc39ed0593929ffd02a45ff583bd89b79c6f646fe9",
		"fd119985533bd5520b301d12",
		"",
		"98e68c10bf4b5ae62d434928fc6405147c6301417303ef3a703dcfd2c0c339a4"
		"d0a89bd29fe61fecf1066ab06d7a5c31a48ffbfed22f749b17e9bd0dc1c6f8fb"
		"d6fd4587184db964d5456132106d782338c3f117ec05229b0899",
		"",
		"cf54e7141349b66f248154427810c87a"
	},
	{
		"31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
		"0d18e06c7c725ac9e362e1ce",
		"2db5168e932556f8089a0622981d017d",
		"",
		"fa4362189661d163fcd6a56d8bf0405a",
		"d636ac1bbedd5cc3ee727dc2ab4a9489"
	},
	{
		"92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b",
		"ac93a1a6145299bde902f21a",
		"2d71bcfa914e4ac045b2aa60955fad24",
		"1e0889016f67601c8ebea4943bc23ad6",
		"8995ae2e6df3dbf96fac7b7137bae67f",
		"eca5aa77d51d4a0a14d9c51e1da474ab"
	},
	{
		"83688deb4af8007f9b713b47cfa6c73e35ea7a3aa4ecdb414dded03bf7a0fd3a",
		"0b459724904e010a46901cf3",
		"33d893a2114ce06fc15d55e454cf90c3",
		"794a14ccd178c8ebfd1379dc704c5e208f9d8424",
		"cc66bee423e3fcd4c0865715e9586696",
		"0fb291bd3dba94a1dfd8b286cfb97ac5"
	},
	{
		"e4fed339c7b0cd267305d11ab0d5c3273632e8872d35bdc367a1363438239a35",
		"0365882cf75432cfd23cbd42",
		"fff39a087de39a03919fbd2f2fa5f513",
		"8a97d2af5d41160ac2ff7dd8ba098e7aa4d618f0f455957d6a6d0801796747ba"
		"57c32dfbaaaf15176528fe3a0e4550c9",
		"8d9e68f03f7e5f4a0ffaa7650d026d08",
		"3554542c478c0635285a61d1b51f6afa"
	},
	{
		"80d755e24d129e68a5259ec2cf618e39317074a83c8961d3768ceb2ed8d5c3d7",
		"7598c07ba7b16cd12cf50813",
		"5e7fd1298c4f15aa0f1c1e47217aa7a9",
		"0e94f4c48fd0c9690c853ad2a5e197c5de262137b69ed0cdfa28d8d12413e4ff"
		"ff15374e1cccb0423e8ed829a954a335ed705a272ad7f9abd1057c849bb0d54b"
		"768e9d79879ec552461cc04adb6ca0040c5dd5bc733d21a93702",
		"5762a38cf3f2fdf3645d2f6696a7eead",
		"8a6708e69468915c5367573924fe1ae3"
	},
	{
		"82c4f12eeec3b2d3d157b0f992d292b237478d2cecc1d5f161389b97f999057a",
		"7b40b20f5f397177990ef2d1",
		"982a296ee1cd7086afad976945",
		"",
		"ec8e05a0471d6b43a59ca5335f",
		"113ddeafc62373cac2f5951bb9165249"
	},
	{
		"dad89d9be9bba138cdcf8752c45b579d7e27c3dbb40f53e771dd8cfd500aa2d5",
		"cfb2aec82cfa6c7d89ee72ff",
		"b526ba1050177d05b0f72f8d67",
		"6e43784a91851a77667a02198e28dc32",
		"8b29e66e924ecae84f6d8f7d68",
		"1e365805c8f28b2ed8a5cadfd9079158"
	},
	{
		"69b458f2644af9020463b40ee503cdf083d693815e2659051ae0d039e606a970",
		"8d1da8ab5f91ccd09205944b",
		"f3e0e09224256bf21a83a5de8d",
		"036ad5e5494ef817a8af2f5828784a4bfedd1653",
		"c0a62d77e6031bfdc6b13ae217",
		"a794a9aaee48cd92e47761bf1baff0af"
	},
	{
		"5f671466378f470ba5f5160e2209f3d95a48b7e560625d5a08654414de23aee2",
		"6b3c08a663d04132243dd96c",
		"c428592d9f8a7f107ec4d0df05",
		"12965559c31d538f937bda6eee9c93b0387318dc5d9496fb1c3a0b9b978dbfeb"
		"ff2a5823974ee9d679834dbe59f7ec51",
		"1d8d7fe4357080c817303ce19c",
		"e88d6b566fdc7b4fd62106bd2eb806ec"
	},
	{
		"ff9506b4d46ba54128876fadfcc673a4c927c618ea7d95cfcaa508cbc8f7fc66",
		"3742ad2208a0484345eee1be",
		"7fd0d6cadc92cad27bb2d7d8c8",
		"f1360a27fdc244be8739d85af6491c762a693aafe668c449515fdeeedb6a90ae"
		"ee3891bbc8b69adc6a6426cb12fcdebc32c9f58c5259d128b91efa28620a3a9a"
		"0168b0ff5e76951cb41647ba4aa1f87fac0d97ac580e42cffc7e",
		"bdb8346b28eb4d7226493611a6",
		"7484d827b767647f44c7f94a39f8175c"
	},
	{
		"268ed1b5d7c9c7304f9cae5fc437b4cd3aebe2ec65f0d85c3918d3d3b5bba89b",
		"9ed9d8180564e0e945f5e5d4",
		"fe29a40d8ebf57262bdb87191d01843f4ca4b2de97d88273154a0b7d9e2fdb80",
		"",
		"791a4a026f16f3a5ea06274bf02baab469860abde5e645f3dd473a5acddeecfc",
		"05b2b74db0662550435ef1900e136b15"
	},
	{
		"37ccdba1d929d6436c16bba5b5ff34deec88ed7df3d15d0f4ddf80c0c731ee1f",
		"5c1b21c8998ed6299006d3f9",
		"ad4260e3cdc76bcc10c7b2c06b80b3be948258e5ef20c508a81f51e96a518388",
		"22ed235946235a85a45bc5fad7140bfa",
		"3b335f8b08d33ccdcad228a74700f1007542a4d1e7fc1ebe3f447fe71af29816",
		"1fbf49cc46f458bf6e88f6370975e6d4"
	},
	{
		"5853c020946b35f2c58ec427152b840420c40029636adcbb027471378cfdde0f",
		"eec313dd07cc1b3e6b068a47",
		"ce7458e56aef9061cb0c42ec2315565e6168f5a6249ffd31610b6d17ab64935e",
		"1389b522c24a774181700553f0246bbabdd38d6f",
		"eadc3b8766a77ded1a58cb727eca2a9790496c298654cda78febf0da16b6903b",
		"3d49a5b32fde7eafcce90079217ffb57"
	},
	{
		"dc776f0156c15d032623854b625c61868e5db84b7b6f9fbd3672f12f0025e0f6",
		"67130951c4a57f6ae7f13241",
		"9378a727a5119595ad631b12a5a6bc8a91756ef09c8d6eaa2b718fe86876da20",
		"fd0920faeb7b212932280a009bac969145e5c316cf3922622c3705c3457c4e9f"
		"124b2076994323fbcfb523f8ed16d241",
		"6d958c20870d401a3c1f7a0ac092c97774d451c09f7aae992a8841ff0ab9d60d",
		"b876831b4ecd7242963b040aa45c4114"
	},
	{
		"26bf255bee60ef0f653769e7034db95b8c791752754e575c761059e9ee8dcf78",
		"cecd97ab07ce57c1612744f5",
		"96983917a036650763aca2b4e927d95ffc74339519ed40c4336dba91edfbf9ad",
		"afebbe9f260f8c118e52b84d8880a34622675faef334cdb41be9385b7d059b79"
		"c0f8a432d25f8b71e781b177fce4d4c57ac5734543e85d7513f96382ff4b2d4b"
		"95b2f1fdbaf9e78bbd1db13a7dd26e8a4ac83a3e8ab42d1d545f",
		"e34b1540a769f7913331d66796e00bdc3ee0f258cf244eb7663375cc5ad6c658",
		"3841f02beb7a7fca7e578922d0a2f80c"
	},
	{
		"1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a",
		"1f3afa4711e9474f32e70462",
		"06b2c75853df9aeb17befd33cea81c630b0fc53667ff45199c629c8e15dce41e"
		"530aa792f796b8138eeab2e86c7b7bee1d40b0",
		"",
		"91fbd061ddc5a7fcc9513fcdfdc9c3a7c5d4d64cedf6a9c24ab8a77c36eefbf1"
		"c5dc00bc50121b96456c8cd8b6ff1f8b3e480f",
		"30096d340f3d5c42d82a6f475def23eb"
	},
	{
		"5fe01c4baf01cbe07796d5aaef6ec1f45193a98a223594ae4f0ef4952e82e330",
		"bd587321566c7f1a5dd8652d",
		"881dc6c7a5d4509f3c4bd2daab08f165ddc204489aa8134562a4eac3d0bcad79"
		"65847b102733bb63d1e5c598ece0c3e5dadddd",
		"9013617817dda947e135ee6dd3653382",
		"16e375b4973b339d3f746c1c5a568bc7526e909ddff1e19c95c94a6ccff210c9"
		"a4a40679de5760c396ac0e2ceb1234f9f5fe26",
		"abd3d26d65a6275f7a4f56b422acab49"
	},
	{
		"24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f",
		"9ff18563b978ec281b3f2794",
		"27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86"
		"757accb158bd9abb3868fdc0d0b074b5f01b2c",
		"adb5ec720ccf9898500028bf34afccbcaca126ef",
		"eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b0614"
		"5dae82057ad55994cf59ad7f67c0fa5e85fab8",
		"bc95c532fecc594c36d1550286a7a3f0"
	},
	{
		"463b412911767d57a0b33969e674ffe7845d313b88c6fe312f3d724be68e1fca",
		"611ce6f9a6880750de7da6cb",
		"e7d1dcf668e2876861940e012fe52a98dacbd78ab63c08842cc9801ea581682a"
		"d54af0c34d0d7f6f59e8ee0bf4900e0fd85042",
		"0a682fbc6192e1b47a5e0868787ffdafe5a50cead3575849990cdd2ea9b35977"
		"49403efb4a56684f0c6bde352d4aeec5",
		"8886e196010cb3849d9c1a182abe1eeab0a5f3ca423c3669a4a8703c0f146e8e"
		"956fb122e0d721b869d2b6fcd4216d7d4d3758",
		"2469cecd70fd98fec9264f71df1aee9a"
	},
	{
		"148579a3cbca86d5520d66c0ec71ca5f7e41ba78e56dc6eebd566fed547fe691",
		"b08a5ea1927499c6ecbfd4e0",
		"9d0b15fdf1bd595f91f8b3abc0f7dec927dfd4799935a1795d9ce00c9b879434"
		"420fe42c275a7cd7b39d638fb81ca52b49dc41",
		"e4f963f015ffbb99ee3349bbaf7e8e8e6c2a71c230a48f9d59860a29091d2747"
		"e01a5ca572347e247d25f56ba7ae8e05cde2be3c97931292c02370208ecd097e"
		"f692687fecf2f419d3200162a6480a57dad408a0dfeb492e2c5d",
		"2097e372950a5e9383c675e89eea1c314f999159f5611344b298cda45e628437"
		"16f215f82ee663919c64002a5c198d7878fd3f",
		"adbecdb0d5c2224d804d2886ff9a5760"
	},
	{
		"98ebf7a58db8b8371d9069171190063cc1fdc1927e49a3385f890d41a838619c",
		"3e6db953bd4e641de644e50a",
		"",
		"",
		"",
		"2fb9c3e41fff24ef07437c47"
	},
	{
		"7c2d25ce3fb3e80e83557d1c5796f1e6af80b120ed35aae379fe47e40490aef7",
		"099f5b34666e9501991d72e1",
		"",
		"dfcab2f0df0e37528426007dcd5abb0e",
		"",
		"c000a9d0a1f8824537ec7700"
	},
	{
		"894be0a22e1ba0279e64ecfebc412aaa72e26a1820b21295dfd29e3f5b97aebd",
		"0e4d1c78085643e39c0d465f",
		"",
		"51859100074ffa193ca70b2565768e1c0a4176ee",
		"",
		"7d209c05edeeca3aaa7f9903"
	},
	{
		"d3800ab29f91eb367c9d201c9933a6d19dd5d8664b430c5a105e8dfc0a206067",
		"dea1eae25d309f8d9939f7cb",
		"",
		"940c27e027ff7e65049bc6c526abb60d3dc06bae4b50a95871321902d21a922f"
		"207a24e87fdbf135b2e4a3a2dce1bfd9",
		"",
		"4374d189859b69012163db65"
	},
	{
		"7cb746fbd70e929a8efa65d16b1aa8a37f5b4478edc686b3a9d31631d5bf114b",
		"2f007847f97273c353af2b18",
		"",
		"17e84902ef33808d450f6d19b19fb3f863ca6c5476fa44105ab09a34ad530b9e"
		"606ebd606529b6d088a513fdf8948ae78f44aff67b6f2429effc126d3c5de8cc"
		"2ca8b9bf7a5b4417c0a8a4f90742637d73acfbb615cde7352463",
		"",
		"44ecc2383ae85a8cbad1f1b0"
	},
	{
		"b33b0e4c5b9f7ef77cec1a29ed5844bda3853238bdf7766e7645029931f169f0",
		"f226d65e8654fdf5193ed721",
		"bcf48ddcfe9d011a1003973d68d2d78a",
		"",
		"d2eb20898a301b5d8e69e99262720213",
		"93af01abb6a970047a7fc010"
	},
	{
		"7bb92a5dc2456789e565c0d825382fb76d551d97a804d18706348b62a09b1ec6",
		"322085c51ddc5b46a1accac2",
		"1cc55a95e925ff93b6cfd5ac99240abd",
		"001db4ea21c94f46fdd0e2c4a3b5c692",
		"509c643c32504945b72bc5a911d5c300",
		"405126600df3b7f2ac44ce4d"
	},
	{
		"02168b4fdd00870a8f9f443e79ee379b676c3c383c60a027b435722ae41af284",
		"62bbebbc68e5423d27fe5d59",
		"08422dd3e9d87ef50a0c989a1088dc1e",
		"4bcc4045752634c528fd9450e56c960ffafdc7fb",
		"9b46212802e81fe366efdb4e279bc9b7",
		"7106445c3261652764102b1d"
	},
	{
		"5adab4454dbbe6094f28f61cacac4cfe574715034579f98f4dd3c09cb6bf5eee",
		"3e898aa4d91135dfdf74ab08",
		"6cb7c3f0398535ca733c4806183d0602",
		"c5b90d2d94468118a34acbb4322ff9240dae2013f9c05fc4101f9068f20cfc98"
		"dd731989c472d4dee578b2e0ff7d89a8",
		"ec293778374d996333559720ad67e51e",
		"af7d96665aa8d4915dd4d579"
	},
	{
		"a8295aeceb223c0a54d33dcbb3d9c55e11f9f0bfe059f4efa93f97841d95af21",
		"97cbbb09f0823fa6e67a4ed5",
		"64a831100d96f43de425e40d75bcf058",
		"aec59ec5e5bb41583ab64b67b3c5d55e07f5e7a9beff6de63143bde4c678553b"
		"da6daf61097844de3a73f2d4e5bd04c533085ebb923732144c573bcb4b7d3d93"
		"ad66127c9532b63ede82efe89f25b1afcab014acb265475bc8c7",
		"7963738ec3377f70f4076a3373306c2e",
		"1f95f93a09f3d4a674796196"
	},
	{
		"ac046f942a82a9dd041e4aaf27ac23a0af57d5914b9fa00224fecf64342b3b55",
		"8aaeb1c35bfb3931d0e627cf",
		"77a0a4a594d8de616b86bab558",
		"",
		"178b93024040a2d2327b80c9b5",
		"87a0dc4660668d217cd98b99"
	},
	{
		"586a41514a5d86abe03c375b6771c4228b316ffdc4c717e18a8403d1d74ecc4d",
		"bea1761d0bdfd0659c7e5ace",
		"d6b0d28dc982c82f617f1a0330",
		"c5e3d5aff6c9ddbec333ac515f56f61b",
		"0c651e00a1f5e9584ec7afe24b",
		"cdc05bd8e15fac64145c68b4"
	},
	{
		"023f36822e90056e7724757b76b3ed6bf72768c829b7b4c65418bea1421d2591",
		"a6e1133fdbcff6f0dc078ec5",
		"d229a1675afb436e15bb06559f",
		"cd366ac6b1967dec58924e4f0736df42d9427ea4",
		"337d3f64caaa6313fd5362e60d",
		"65804c7d58bdc20599231598"
	},
	{
		"1eacdaa27bfb7a065bab598d56ae9f7de7399ee9b98e7832585658395aae38ae",
		"f1e29d9b54e1b2b15c842f40",
		"01b1fea63001163c13151222d3",
		"73ad0e5a1501ef46a51289868bc1a9d2bd8fd362591d28f146cccf3f7e990fde"
		"1d438bae2d8614bc6c78dbd1da10e242",
		"cedd626f0808a621eb7ae59d59",
		"f6e7b6967f3669b1589006b9"
	},
	{
		"512903e96ba584dbef3a6e702b0adb51fb3bb62e89d39fd5d2490ae6a4e80c88",
		"056ee9b8c34e3549661d36da",
		"e13300959560f2aea376ab3e96",
		"0918b88fc87e640212448e7a3574428f65ce7fb0ce77462ee1735b6d22cc6c7c"
		"06a39e04a0147faeaa46925092359032156a5a7105373692f7f8ace4e697d0c8"
		"10092a3a584dfe43d35c94e22dafc169b5d931bba17e5eab3299",
		"bc869e464531babc2d2e94fa1b",
		"e01c6c9c01c15efb9dbc6bfe"
	},
	{
		"35fdd9201681904f00e072faceebd688d5937ac8960c216bf7d8378d8574b154",
		"2477336871ce777e748f892a",
		"624c99399594cda1cc25792d34fd096280d1622dcb9b5ed65e1f16974b0bfd11",
		"",
		"a3a61ded49ed78b2cfbabd9d94f0ffdc0d5ffa5b248cff173889c414d64eb0cc",
		"d5c1e7f9475b4183f469e896"
	},
	{
		"185cded583eba7f3d06cb5dc9d23fa6c51d27d1336206c1c2938fe771751831a",
		"b2b6853541e56cd85f7f2b4b",
		"133f837fabd08eb5970936ae65d64bfd556020900a1d16a549564c6243fac494",
		"58ee0bd99a31b79002fd43e9f0c8718d",
		"847e3d4dc053f741a843b3c7d959529214e04c9891f9d5b490d74caa73ac4af1",
		"9f728944fa967e3033f8c23f"
	},
	{
		"f1dbae7f4e6978de87ca7d950daf402e58155a325bd4dba03a2473307ba14ef0",
		"4c6d21dfdaad3e0888b0177a",
		"a4bb48e22a91c52ec5e0f8df31abf7af2f2032b2e1dbc8ad73c32cbcb8ed47ee",
		"c9d79aba7ef84c2f726aba61bfd5d07d4fc2fb41",
		"36795e4a034c96d6f2009845ae8c20a6b5318b62b41634f26a9e96ded6ec6490",
		"0158ce9cd418eac9239e2691"
	},
	{
		"e29e006956c7532d40bd56df5f565d57ee1ea49037404cca7b6ea9dc9e36ab0f",
		"ed2caad30eb367d2d89a5ffb",
		"b982ea6ff68af4c5202d71466f9f9f63614ad5378859a62d7a38ee32aa370bd9",
		"416a7b1db963ed683fd91bc2c5e9df3998944c3d0cbea2d2302c8a6724997352"
		"5d0dbe8d13f806174dd983ab18854ae6",
		"656539e12450db9dd88e4113f7890e80c6186768e6c8b1fc869c42dfad7b58bf",
		"4366e2ce0396f0410ebcb893"
	},
	{
		"ca42f7d449a0275d3194dcf2f5632115381182c4d992cdef9d4c6ab22cafb37a",
		"f7db8f8db3323d35df706071",
		"ff1d07d9ea9460fa5c1c160e86115ccc53c4fe5aad702da73d963c02ea529edc",
		"d3e3ad01af662dc32aec49d11664721f6f928d89e095764ea213ecdd7520a601"
		"21729832cf33ed8441ee671d1c451cf7e6844d3e400279994b37a6c9c9c64d9b"
		"e4d0cc16507fa49fddf98a62e45b8a8293e660943a89fa48d9e4",
		"4ef5360e43d9b9b6c954ddf0543e1488a5f2e1423f85cc389512d02a5508f036",
		"27529e3fa0f97e60529dbe95"
	},
	{
		"9b68ca2ae9e68c34442bcd965b9409e6de074149b50d3905455e5192594d2555",
		"00f6ebb531cae6d76f319aea",
		"9aa0d8f8f09dedb4698348649e00ef409a3593de90b419b05795faad3717aa02"
		"d2a9b0a0080f5dbc97bb48b1ae556b95bffbfe",
		"",
		"10fffecadb350845281380fdeeb27879567436a077580384b98f0c839be16958"
		"8ecb67883137ef8cead0b7a7b6882891ea24a7",
		"a6e6694aa52b8cdd7d656d13"
	},
	{
		"96ac126b5b0ed0890b893657afa4c274ce300cb480cce961c27ddbc61e30783c",
		"ee9e54a316ced1374a13ca2e",
		"b4786d6bda2dd17690f5b0df362f539c54e7e1cd2cd0ac1f0acfaa51d6730957"
		"29f88db1b6dd54be0b62d349e56557aa4e4980",
		"396d0892aff3212995e8f564083a0972",
		"df5af7ef15164d9faf062ab23356f7c4313bb9b05612de9e051ec31af83d7ff9"
		"f34e51143dfd43ab84a38f8950208653f1ff54",
		"9516b2653b1b06562bfca914"
	},
	{
		"fd17fcb1d6fe1dca0d75fc26824a4e9286886fec83d56e02cabbb2b37a33a377",
		"97ae56d9d1224c5d1491ce13",
		"48ae872cb2eeefc0078b6cc484fd32423dd9136b0d09e2f92fadef8d3118fba2"
		"4fa1fc3d208dcc666cc50406377ab577a0fa06",
		"d29df4f2846a13e427e67679644d25282355ab69",
		"770b8883e0af9e410431121569ce83f21f32be7ff8f89413b0263440c084f2cb"
		"fa3258c62d1ddd70043c42cb74412548e9e5e6",
		"7f4adaad38c1a823c0b2ecb4"
	},
	{
		"90219f2067a4951ec42c4a0f43f0cde9f64f9a459902a3ebb6545dc8c2dd2abf",
		"38afdfc54c81ba4de3315e8d",
		"24a3e1c260230ce14fbb0a2c1b2c066244896bb0f71d816681b9ebdc7ed6ac2e"
		"a4b9720310a274cd2cb225df0ba4dc3c246afc",
		"5f41b44d7b23de298019c3cb1d71c564ae506fda3e2af14af9fd56b085abf207"
		"a6ad13fb99b5f400dd0607b7f9d72662",
		"d1e97d3b52e3d3f696f6abf08b0329f723fa5a25482515e05870c1c02f93e94e"
		"15b1c3bad9b69e1dbdf80994d878f529170fb2",
		"9d7caea02b4023d8d11e2d2d"
	},
	{
		"54a2e564d9796ba66e7e4f1456782f08a921b097dfb0f62302b02f0473c770ca",
		"9efca71be89b11b857c9cc80",
		"50205d7a3fcc71ebd386e48a421bcdaf3287cf78df1c10921fe85855ccc07a70"
		"1623260d7992aa48103865402efa12b0cb8a71",
		"3debc7ce4501dea63152206eb8ca2f8c41824a0d4e7f95488497eec76230bdab"
		"0663f22c0b94b17f077ae914d661710fe93756f48ac02d378abf49c129889fc4"
		"beb502f61cfd2374a76d979e45f4630fd2a3ca7d3fb3574c98b9",
		"4b41f4e02f7e71eab4dfd1b3b4457e0c0459a9581f550cb8766ebc2c30e26847"
		"d95ef3fc6cec5d1cf5cbe1720f6936307ed7b8",
		"ba9821b0d7f4327db5228640"
	},
};

static void known_answers(void)
{
	uint8_t key[32], iv[12], pt[512], aad[512], expected[512], expected_tag[16];
	uint8_t output[512], recovered[512], tag[16];

	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
		size_t length, aad_length, tag_length;

		check(decode(key, sizeof(key), vectors[i].key) == 32, "key size");
		check(decode(iv, sizeof(iv), vectors[i].iv) == 12, "IV size");
		length = decode(pt, sizeof(pt), vectors[i].pt);
		aad_length = decode(aad, sizeof(aad), vectors[i].aad);
		check(decode(expected, sizeof(expected), vectors[i].ct) == length, "ciphertext size");
		tag_length = decode(expected_tag, sizeof(expected_tag), vectors[i].tag);
		check(tag_length == 12 || tag_length == 16, "tag size");
		check(aes_256_gcm_encrypt(output, sizeof(output), tag, tag_length, pt, length, aad, aad_length, iv, key),
			"encrypt");
		check(!memcmp(output, expected, length) && !memcmp(tag, expected_tag, tag_length), "NIST ciphertext and tag");
		check(aes_256_gcm_decrypt(recovered, sizeof(recovered), expected, length, aad, aad_length,
			expected_tag, tag_length, iv, key), "decrypt NIST vector");
		check(!memcmp(recovered, pt, length), "NIST plaintext");
		memcpy(output, pt, length);
		check(aes_256_gcm_encrypt(output, length, tag, tag_length, output, length, aad, aad_length, iv, key),
			"in-place encrypt");
		check(!memcmp(output, expected, length) && !memcmp(tag, expected_tag, tag_length), "in-place known answer");
		check(aes_256_gcm_decrypt(output, length, output, length, aad, aad_length, tag, tag_length, iv, key),
			"in-place decrypt");
		check(!memcmp(output, pt, length), "in-place plaintext");
	}
}

static void failure_tests(size_t tag_length)
{
	uint8_t key[32] = {0}, iv[12] = {0}, pt[20] = {0};
	uint8_t aad[] = "ADSB Aggregator CLI:mike:$6$example";
	uint8_t ciphertext[20], tag[16] = {0}, original_tag[16] = {0}, output[20], snapshot[20];
	uint8_t original_ciphertext[20];

	check(aes_256_gcm_encrypt(ciphertext, 20, tag, tag_length, pt, 20, aad, sizeof(aad) - 1, iv, key), "20-byte OTP seed");
	memcpy(original_tag, tag, 16);
	memcpy(original_ciphertext, ciphertext, 20);
	/* Flip every bit in every authenticated input independently. */
	for (unsigned int field = 0; field < 5; ++field) {
		uint8_t *p = field == 0 ? tag : field == 1 ? ciphertext : field == 2 ? aad : field == 3 ? iv : key;
		size_t length = field == 0 ? tag_length : field == 1 ? 20 : field == 2 ? sizeof(aad) - 1 : field == 3 ? 12 : 32;

		for (size_t bit = 0; bit < length * 8; ++bit) {
			p[bit / 8] ^= (uint8_t)(1U << (bit % 8));
			memset(output, 0xa5, sizeof(output));
			memcpy(snapshot, output, sizeof(output));
			check(!aes_256_gcm_decrypt(output, 20, ciphertext, 20, aad, sizeof(aad) - 1, tag, tag_length, iv, key),
				"modified authenticated input rejected");
			check(!memcmp(output, snapshot, 20), "failed authentication releases no plaintext");
			p[bit / 8] ^= (uint8_t)(1U << (bit % 8));
		}
	}
	tag[0] ^= 1;
	check(!aes_256_gcm_decrypt(ciphertext, 20, ciphertext, 20, aad, sizeof(aad) - 1, tag, tag_length, iv, key),
		"in-place bad tag rejected");
	check(!memcmp(ciphertext, original_ciphertext, 20), "in-place bad tag preserves ciphertext");
	memcpy(tag, original_tag, 16);
	check(aes_256_gcm_decrypt(output, 20, ciphertext, 20, aad, sizeof(aad) - 1, tag, tag_length, iv, key),
		"original inputs work");
	check(!memcmp(output, pt, 20), "original plaintext restored");
}

static void invalid_arguments(void)
{
	uint8_t key[32] = {0}, iv[12] = {0}, data[64], before[64], tag[16], tag_before[16];

	memset(data, 0xa5, sizeof(data));
	memset(tag, 0x5a, sizeof(tag));
	memcpy(before, data, sizeof(data));
	memcpy(tag_before, tag, sizeof(tag));
	check(!aes_256_gcm_encrypt(data, 19, tag, 16, data, 20, NULL, 0, iv, key), "short encryption output");
	check(!aes_256_gcm_decrypt(data, 19, data, 20, NULL, 0, tag, 16, iv, key), "short decryption output");
	check(!aes_256_gcm_encrypt(data, 20, tag, 16, data, 20, NULL, 1, iv, key), "NULL nonempty AAD");
	check(!aes_256_gcm_encrypt(NULL, 20, tag, 16, data, 20, NULL, 0, iv, key), "NULL nonempty output");
	check(!aes_256_gcm_encrypt(data, 20, tag, 16, NULL, 20, NULL, 0, iv, key), "NULL nonempty input");
	check(!aes_256_gcm_encrypt(data, 20, NULL, 16, data, 20, NULL, 0, iv, key), "NULL tag");
	check(!aes_256_gcm_encrypt(data, 20, tag, 16, data, 20, NULL, 0, NULL, key), "NULL IV");
	check(!aes_256_gcm_encrypt(data, 20, tag, 16, data, 20, NULL, 0, iv, NULL), "NULL key");
	check(!aes_256_gcm_encrypt(data + 1, 20, tag, 16, data, 20, NULL, 0, iv, key), "shifted overlap");
	check(!aes_256_gcm_encrypt(data, 20, data + 8, 16, data, 20, NULL, 0, iv, key), "tag/output overlap");
	check(!aes_256_gcm_encrypt(data, 20, tag, 16, data + 32, 20, data, 20, iv, key), "AAD/output overlap");
	check(!aes_256_gcm_encrypt(data, 20, tag, 16, data + 32, 20, NULL, 0, iv, data), "key/output overlap");
	check(!aes_256_gcm_encrypt(data, 20, tag, 16, data + 32, 20, NULL, 0, data, key), "IV/output overlap");
	if (SIZE_MAX > UINT32_MAX) {
		size_t too_large = (size_t)AES_256_GCM_MAX_DATA_SIZE + 1;

		check(!aes_256_gcm_encrypt(data, too_large, tag, 16, data, too_large, NULL, 0, iv, key), "GCM data limit");
		check(!aes_256_gcm_decrypt(data, too_large, data, too_large, NULL, 0, tag, 16, iv, key), "decrypt data limit");
		check(!aes_256_gcm_encrypt(data, 20, tag, 16, data, 20, data + 32, SIZE_MAX, iv, key), "AAD bit-length overflow");
	}
	check(!memcmp(data, before, sizeof(data)), "invalid calls leave output untouched");
	check(!memcmp(tag, tag_before, sizeof(tag)), "invalid calls leave tag untouched");
	check(aes_256_gcm_encrypt(NULL, 0, tag, 16, NULL, 0, NULL, 0, iv, key), "empty message/empty AAD");
	check(aes_256_gcm_decrypt(NULL, 0, NULL, 0, NULL, 0, tag, 16, iv, key), "empty message verifies");
	tag[0] ^= 1;
	check(!aes_256_gcm_decrypt(NULL, 0, NULL, 0, NULL, 0, tag, 16, iv, key), "empty message bad tag");
}

static void short_tag_buffers(void)
{
	uint8_t key[32] = {0}, iv[12] = {0}, data[20] = {0}, output[20];
	uint8_t guarded[14], tag_before[16], tag[16];
	uint8_t *exact = malloc(12);
	static const size_t invalid[] = {0, 8, 11, 13, 15, 17, SIZE_MAX};

	check(exact != NULL, "allocate exact 12-byte tag buffer");
	memset(guarded, 0xa5, sizeof(guarded));
	check(aes_256_gcm_encrypt(output, 20, guarded + 1, 12, data, 20, NULL, 0, iv, key), "12-byte tag encryption");
	check(guarded[0] == 0xa5 && guarded[13] == 0xa5, "12-byte tag write canaries");
	memcpy(exact, guarded + 1, 12);
	check(aes_256_gcm_decrypt(output, 20, output, 20, NULL, 0, exact, 12, iv, key), "exact 12-byte read buffer");
	check(!memcmp(output, data, 20), "12-byte-tag plaintext");
	memset(tag, 0xa5, sizeof(tag));
	memcpy(tag_before, tag, sizeof(tag));
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
		check(!aes_256_gcm_encrypt(output, 20, tag, invalid[i], data, 20, NULL, 0, iv, key), "invalid tag size rejected");
		check(!aes_256_gcm_decrypt(output, 20, data, 20, NULL, 0, tag, invalid[i], iv, key), "invalid decrypt tag size");
	}
	check(!memcmp(tag, tag_before, 16), "invalid tag size leaves tag unchanged");
	check(aes_256_gcm_encrypt(NULL, 0, exact, 12, NULL, 0, NULL, 0, iv, key), "empty message with 96-bit tag");
	check(aes_256_gcm_decrypt(NULL, 0, NULL, 0, NULL, 0, exact, 12, iv, key), "empty message verifies 96-bit tag");
	free(exact);
}

int main(void)
{
	known_answers();
	failure_tests(12);
	failure_tests(16);
	invalid_arguments();
	short_tag_buffers();
	printf("PASS: %u AES-256-GCM checks (%zu NIST CAVP vectors)\n", checks, sizeof(vectors) / sizeof(vectors[0]));
	return EXIT_SUCCESS;
}
