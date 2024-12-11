import { strict as assert } from 'assert';
import signify, {
    Saider,
    CredentialSubject,
    CredentialData,
    CreateIdentiferArgs,
    randomNonce,
    Salter,
    HabState,
    SignifyClient,
    Serder,
    IssueCredentialResult,
} from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env';
import {
    resolveOobi,
    waitOperation,
    getOrCreateAID,
    getOrCreateClients,
    getOrCreateContact,
    createTimestamp,
    getIssuedCredential,
    getReceivedCredential,
    waitForCredential,
    admitSinglesig,
    waitAndMarkNotification,
    assertOperations,
    warnNotifications
} from './utils/test-util';
import {
    addEndRoleMultisig,
    admitMultisig,
    createAIDMultisig,
    createRegistryMultisig,
    delegateMultisig,
    grantMultisig,
    issueCredentialMultisig,
} from './utils/multisig-utils';

const { vleiServerUrl, witnessIds } = resolveEnvironment();

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const LE_SCHEMA_SAID = 'ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY';
const ECR_SCHEMA_SAID = 'EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw';

const vLEIServerHostUrl = `${vleiServerUrl}/oobi`;
const QVI_SCHEMA_URL = `${vLEIServerHostUrl}/${QVI_SCHEMA_SAID}`;
const LE_SCHEMA_URL = `${vLEIServerHostUrl}/${LE_SCHEMA_SAID}`;
const ECR_SCHEMA_URL = `${vLEIServerHostUrl}/${ECR_SCHEMA_SAID}`;

const qviData = {
    LEI: '254900OPPU84GM83MG36',
};

const leData = {
    LEI: '875500ELOZEL05BVXV37',
};

const ecrData = {
    LEI: leData.LEI,
    personLegalName: 'John Doe',
    engagementContextRole: 'EBA Submitter',
};

const LE_RULES = Saider.saidify({
    d: '',
    usageDisclaimer: {
        l: 'Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.',
    },
    issuanceDisclaimer: {
        l: 'All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.',
    },
})[1];

const ECR_RULES = Saider.saidify({
    d: '',
    usageDisclaimer: {
        l: 'Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.',
    },
    issuanceDisclaimer: {
        l: 'All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.',
    },
    privacyDisclaimer: {
        l: 'It is the sole responsibility of Holders as Issuees of an ECR vLEI Credential to present that Credential in a privacy-preserving manner using the mechanisms provided in the Issuance and Presentation Exchange (IPEX) protocol specification and the Authentic Chained Data Container (ACDC) specification. https://github.com/WebOfTrust/IETF-IPEX and https://github.com/trustoverip/tswg-acdc-specification.',
    },
})[1];


const ECR_AUTH_SCHEMA_SAID = 'EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g';
const OOR_AUTH_SCHEMA_SAID = 'EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E';
const OOR_SCHEMA_SAID = 'EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy';
const ECR_AUTH_SCHEMA_URL = `${vLEIServerHostUrl}/${ECR_AUTH_SCHEMA_SAID}`;
const OOR_AUTH_SCHEMA_URL = `${vLEIServerHostUrl}/${OOR_AUTH_SCHEMA_SAID}`;
const OOR_SCHEMA_URL = `${vLEIServerHostUrl}/${OOR_SCHEMA_SAID}`;



test('multisig-vlei-issuance', async function run() {
    /**
     * The abbreviations used in this script follows GLEIF vLEI
     * ecosystem governance framework (EGF).
     *      GEDA: GLEIF External Delegated AID
     *      QVI:  Qualified vLEI Issuer
     *      LE:   Legal Entity
     *      GAR:  GLEIF Authorized Representative
     *      QAR:  Qualified vLEI Issuer Authorized Representative
     *      LAR:  Legal Entity Authorized Representative
     *      ECR:  Engagement Context Role Person
     */

    const [
        clientGAR1,
        clientGAR2,
        clientQAR1,
        clientQAR2,
        clientQAR3,
        clientLAR1,
        clientLAR2,
        clientLAR3,
        clientECR,
    ] = await getOrCreateClients(9);

    const kargsAID = {
        toad: witnessIds.length,
        wits: witnessIds,
    };
    const [
        aidGAR1,
        aidGAR2,
        aidQAR1,
        aidQAR2,
        aidQAR3,
        aidLAR1,
        aidLAR2,
        aidLAR3,
        aidECR,
    ] = await Promise.all([
        getOrCreateAID(clientGAR1, 'GAR1', kargsAID),
        getOrCreateAID(clientGAR2, 'GAR2', kargsAID),
        getOrCreateAID(clientQAR1, 'QAR1', kargsAID),
        getOrCreateAID(clientQAR2, 'QAR2', kargsAID),
        getOrCreateAID(clientQAR3, 'QAR3', kargsAID),
        getOrCreateAID(clientLAR1, 'LAR1', kargsAID),
        getOrCreateAID(clientLAR2, 'LAR2', kargsAID),
        getOrCreateAID(clientLAR3, 'LAR3', kargsAID),
        getOrCreateAID(clientECR, 'ECR', kargsAID),
    ]);

    const [
        oobiGAR1,
        oobiGAR2,
        oobiQAR1,
        oobiQAR2,
        oobiQAR3,
        oobiLAR1,
        oobiLAR2,
        oobiLAR3,
        oobiECR,
    ] = await Promise.all([
        clientGAR1.oobis().get('GAR1', 'agent'),
        clientGAR2.oobis().get('GAR2', 'agent'),
        clientQAR1.oobis().get('QAR1', 'agent'),
        clientQAR2.oobis().get('QAR2', 'agent'),
        clientQAR3.oobis().get('QAR3', 'agent'),
        clientLAR1.oobis().get('LAR1', 'agent'),
        clientLAR2.oobis().get('LAR2', 'agent'),
        clientLAR3.oobis().get('LAR3', 'agent'),
        clientECR.oobis().get('ECR', 'agent'),
    ]);

    await Promise.all([
        getOrCreateContact(clientGAR1, 'GAR2', oobiGAR2.oobis[0]),
        getOrCreateContact(clientGAR2, 'GAR1', oobiGAR1.oobis[0]),
        getOrCreateContact(clientQAR1, 'QAR2', oobiQAR2.oobis[0]),
        getOrCreateContact(clientQAR1, 'QAR3', oobiQAR3.oobis[0]),
        getOrCreateContact(clientQAR2, 'QAR1', oobiQAR1.oobis[0]),
        getOrCreateContact(clientQAR2, 'QAR3', oobiQAR3.oobis[0]),
        getOrCreateContact(clientQAR3, 'QAR1', oobiQAR1.oobis[0]),
        getOrCreateContact(clientQAR3, 'QAR2', oobiQAR2.oobis[0]),
        getOrCreateContact(clientLAR1, 'LAR2', oobiLAR2.oobis[0]),
        getOrCreateContact(clientLAR1, 'LAR3', oobiLAR3.oobis[0]),
        getOrCreateContact(clientLAR2, 'LAR1', oobiLAR1.oobis[0]),
        getOrCreateContact(clientLAR2, 'LAR3', oobiLAR3.oobis[0]),
        getOrCreateContact(clientLAR3, 'LAR1', oobiLAR1.oobis[0]),
        getOrCreateContact(clientLAR3, 'LAR2', oobiLAR2.oobis[0]),
        getOrCreateContact(clientLAR1, 'ECR', oobiECR.oobis[0]),
        getOrCreateContact(clientLAR2, 'ECR', oobiECR.oobis[0]),
        getOrCreateContact(clientLAR3, 'ECR', oobiECR.oobis[0]),
    ]);

    await Promise.all([
        resolveOobi(clientGAR1, QVI_SCHEMA_URL),
        resolveOobi(clientGAR2, QVI_SCHEMA_URL),
        resolveOobi(clientQAR1, QVI_SCHEMA_URL),
        resolveOobi(clientQAR1, LE_SCHEMA_URL),
        resolveOobi(clientQAR2, QVI_SCHEMA_URL),
        resolveOobi(clientQAR2, LE_SCHEMA_URL),
        resolveOobi(clientQAR3, QVI_SCHEMA_URL),
        resolveOobi(clientQAR3, LE_SCHEMA_URL),
        resolveOobi(clientLAR1, QVI_SCHEMA_URL),
        resolveOobi(clientLAR1, LE_SCHEMA_URL),
        resolveOobi(clientLAR1, ECR_SCHEMA_URL),
        resolveOobi(clientLAR2, QVI_SCHEMA_URL),
        resolveOobi(clientLAR2, LE_SCHEMA_URL),
        resolveOobi(clientLAR2, ECR_SCHEMA_URL),
        resolveOobi(clientLAR3, QVI_SCHEMA_URL),
        resolveOobi(clientLAR3, LE_SCHEMA_URL),
        resolveOobi(clientLAR3, ECR_SCHEMA_URL),
        resolveOobi(clientECR, QVI_SCHEMA_URL),
        resolveOobi(clientECR, LE_SCHEMA_URL),
        resolveOobi(clientECR, ECR_SCHEMA_URL),

        resolveOobi(clientQAR1, ECR_SCHEMA_URL),
        resolveOobi(clientQAR2, ECR_SCHEMA_URL),
        resolveOobi(clientQAR3, ECR_SCHEMA_URL),
        resolveOobi(clientQAR1, ECR_AUTH_SCHEMA_URL),
        resolveOobi(clientQAR2, ECR_AUTH_SCHEMA_URL),
        resolveOobi(clientQAR3, ECR_AUTH_SCHEMA_URL),
        resolveOobi(clientLAR1, ECR_AUTH_SCHEMA_URL),
        resolveOobi(clientLAR2, ECR_AUTH_SCHEMA_URL),
        resolveOobi(clientLAR3, ECR_AUTH_SCHEMA_URL),
        resolveOobi(clientQAR1, OOR_SCHEMA_URL),
        resolveOobi(clientQAR2, OOR_SCHEMA_URL),
        resolveOobi(clientQAR3, OOR_SCHEMA_URL),
        resolveOobi(clientQAR1, OOR_AUTH_SCHEMA_URL),
        resolveOobi(clientQAR2, OOR_AUTH_SCHEMA_URL),
        resolveOobi(clientQAR3, OOR_AUTH_SCHEMA_URL),
        resolveOobi(clientLAR1, OOR_AUTH_SCHEMA_URL),
        resolveOobi(clientLAR2, OOR_AUTH_SCHEMA_URL),
        resolveOobi(clientLAR3, OOR_AUTH_SCHEMA_URL),
        resolveOobi(clientECR, OOR_SCHEMA_URL),
    ]);

    // Create a multisig AID for the GEDA.
    // Skip if a GEDA AID has already been incepted.
    let aidGEDAbyGAR1, aidGEDAbyGAR2: HabState;
    try {
        aidGEDAbyGAR1 = await clientGAR1.identifiers().get('GEDA');
        aidGEDAbyGAR2 = await clientGAR2.identifiers().get('GEDA');
    } catch {
        const rstates = [aidGAR1.state, aidGAR2.state];
        const states = rstates;

        const kargsMultisigAID: CreateIdentiferArgs = {
            algo: signify.Algos.group,
            isith: ['1/2', '1/2'],
            nsith: ['1/2', '1/2'],
            toad: kargsAID.toad,
            wits: kargsAID.wits,
            states: states,
            rstates: rstates,
        };

        kargsMultisigAID.mhab = aidGAR1;
        const multisigAIDOp1 = await createAIDMultisig(
            clientGAR1,
            aidGAR1,
            [aidGAR2],
            'GEDA',
            kargsMultisigAID,
            true
        );
        kargsMultisigAID.mhab = aidGAR2;
        const multisigAIDOp2 = await createAIDMultisig(
            clientGAR2,
            aidGAR2,
            [aidGAR1],
            'GEDA',
            kargsMultisigAID
        );

        await Promise.all([
            waitOperation(clientGAR1, multisigAIDOp1),
            waitOperation(clientGAR2, multisigAIDOp2),
        ]);

        await waitAndMarkNotification(clientGAR1, '/multisig/icp');

        aidGEDAbyGAR1 = await clientGAR1.identifiers().get('GEDA');
        aidGEDAbyGAR2 = await clientGAR2.identifiers().get('GEDA');
    }
    assert.equal(aidGEDAbyGAR1.prefix, aidGEDAbyGAR2.prefix);
    assert.equal(aidGEDAbyGAR1.name, aidGEDAbyGAR2.name);
    const aidGEDA = aidGEDAbyGAR1;

    // Add endpoint role authorization for all GARs' agents.
    // Skip if they have already been authorized.
    let [oobiGEDAbyGAR1, oobiGEDAbyGAR2] = await Promise.all([
        clientGAR1.oobis().get(aidGEDA.name, 'agent'),
        clientGAR2.oobis().get(aidGEDA.name, 'agent'),
    ]);
    if (oobiGEDAbyGAR1.oobis.length == 0 || oobiGEDAbyGAR2.oobis.length == 0) {
        const timestamp = createTimestamp();
        const opList1 = await addEndRoleMultisig(
            clientGAR1,
            aidGEDA.name,
            aidGAR1,
            [aidGAR2],
            aidGEDA,
            timestamp,
            true
        );
        const opList2 = await addEndRoleMultisig(
            clientGAR2,
            aidGEDA.name,
            aidGAR2,
            [aidGAR1],
            aidGEDA,
            timestamp
        );

        await Promise.all(opList1.map((op) => waitOperation(clientGAR1, op)));
        await Promise.all(opList2.map((op) => waitOperation(clientGAR2, op)));

        await waitAndMarkNotification(clientGAR1, '/multisig/rpy');

        [oobiGEDAbyGAR1, oobiGEDAbyGAR2] = await Promise.all([
            clientGAR1.oobis().get(aidGEDA.name, 'agent'),
            clientGAR2.oobis().get(aidGEDA.name, 'agent'),
        ]);
    }
    assert.equal(oobiGEDAbyGAR1.role, oobiGEDAbyGAR2.role);
    assert.equal(oobiGEDAbyGAR1.oobis[0], oobiGEDAbyGAR2.oobis[0]);

    // QARs, LARs, ECR resolve GEDA's OOBI
    const oobiGEDA = oobiGEDAbyGAR1.oobis[0].split('/agent/')[0];
    await Promise.all([
        getOrCreateContact(clientQAR1, aidGEDA.name, oobiGEDA),
        getOrCreateContact(clientQAR2, aidGEDA.name, oobiGEDA),
        getOrCreateContact(clientQAR3, aidGEDA.name, oobiGEDA),
        getOrCreateContact(clientLAR1, aidGEDA.name, oobiGEDA),
        getOrCreateContact(clientLAR2, aidGEDA.name, oobiGEDA),
        getOrCreateContact(clientLAR3, aidGEDA.name, oobiGEDA),
        getOrCreateContact(clientECR, aidGEDA.name, oobiGEDA),
    ]);


    // Create a multisig AID for the QVI.
    // Skip if a QVI AID has already been incepted.
    let aidQVIbyQAR1, aidQVIbyQAR2, aidQVIbyQAR3: HabState;
    try {
        aidQVIbyQAR1 = await clientQAR1.identifiers().get('QVI');
        aidQVIbyQAR2 = await clientQAR2.identifiers().get('QVI');
        aidQVIbyQAR3 = await clientQAR3.identifiers().get('QVI');
    } catch {
        const rstates = [aidQAR1.state, aidQAR2.state, aidQAR3.state];
        const states = rstates;

        const kargsMultisigAID: CreateIdentiferArgs = {
            algo: signify.Algos.group,
            isith: ['2/3', '1/2', '1/2'],
            nsith: ['2/3', '1/2', '1/2'],
            toad: kargsAID.toad,
            wits: kargsAID.wits,
            states: states,
            rstates: rstates,
            delpre: aidGEDA.prefix,
        };

        kargsMultisigAID.mhab = aidQAR1;
        const multisigAIDOp1 = await createAIDMultisig(
            clientQAR1,
            aidQAR1,
            [aidQAR2, aidQAR3],
            'QVI',
            kargsMultisigAID,
            true
        );
        kargsMultisigAID.mhab = aidQAR2;
        const multisigAIDOp2 = await createAIDMultisig(
            clientQAR2,
            aidQAR2,
            [aidQAR1, aidQAR3],
            'QVI',
            kargsMultisigAID
        );
        kargsMultisigAID.mhab = aidQAR3;
        const multisigAIDOp3 = await createAIDMultisig(
            clientQAR3,
            aidQAR3,
            [aidQAR1, aidQAR2],
            'QVI',
            kargsMultisigAID
        );

        const aidQVIPrefix = multisigAIDOp1.name.split('.')[1];
        assert.equal(multisigAIDOp2.name.split('.')[1], aidQVIPrefix);
        assert.equal(multisigAIDOp3.name.split('.')[1], aidQVIPrefix);

        // GEDA anchors delegation with an interaction event.
        const anchor = {
            i: aidQVIPrefix,
            s: '0',
            d: aidQVIPrefix,
        };
        const ixnOp1 = await delegateMultisig(
            clientGAR1,
            aidGAR1,
            [aidGAR2],
            aidGEDA,
            anchor,
            true
        );
        const ixnOp2 = await delegateMultisig(
            clientGAR2,
            aidGAR2,
            [aidGAR1],
            aidGEDA,
            anchor
        );
        await Promise.all([
            waitOperation(clientGAR1, ixnOp1),
            waitOperation(clientGAR2, ixnOp2),
        ]);

        await waitAndMarkNotification(clientGAR1, '/multisig/ixn');

        // QARs query the GEDA's key state
        const queryOp1 = await clientQAR1
            .keyStates()
            .query(aidGEDA.prefix, '1');
        const queryOp2 = await clientQAR2
            .keyStates()
            .query(aidGEDA.prefix, '1');
        const queryOp3 = await clientQAR3
            .keyStates()
            .query(aidGEDA.prefix, '1');

        await Promise.all([
            waitOperation(clientQAR1, multisigAIDOp1),
            waitOperation(clientQAR2, multisigAIDOp2),
            waitOperation(clientQAR3, multisigAIDOp3),
            waitOperation(clientQAR1, queryOp1),
            waitOperation(clientQAR2, queryOp2),
            waitOperation(clientQAR3, queryOp3),
        ]);

        await waitAndMarkNotification(clientQAR1, '/multisig/icp');

        aidQVIbyQAR1 = await clientQAR1.identifiers().get('QVI');
        aidQVIbyQAR2 = await clientQAR2.identifiers().get('QVI');
        aidQVIbyQAR3 = await clientQAR3.identifiers().get('QVI');
    }
    assert.equal(aidQVIbyQAR1.prefix, aidQVIbyQAR2.prefix);
    assert.equal(aidQVIbyQAR1.prefix, aidQVIbyQAR3.prefix);
    assert.equal(aidQVIbyQAR1.name, aidQVIbyQAR2.name);
    assert.equal(aidQVIbyQAR1.name, aidQVIbyQAR3.name);
    const aidQVI = aidQVIbyQAR1;

    // Add endpoint role authorization for all QARs' agents.
    // Skip if they have already been authorized.
    let [oobiQVIbyQAR1, oobiQVIbyQAR2, oobiQVIbyQAR3] = await Promise.all([
        clientQAR1.oobis().get(aidQVI.name, 'agent'),
        clientQAR2.oobis().get(aidQVI.name, 'agent'),
        clientQAR3.oobis().get(aidQVI.name, 'agent'),
    ]);
    if (
        oobiQVIbyQAR1.oobis.length == 0 ||
        oobiQVIbyQAR2.oobis.length == 0 ||
        oobiQVIbyQAR3.oobis.length == 0
    ) {
        const timestamp = createTimestamp();
        const opList1 = await addEndRoleMultisig(
            clientQAR1,
            aidQVI.name,
            aidQAR1,
            [aidQAR2, aidQAR3],
            aidQVI,
            timestamp,
            true
        );
        const opList2 = await addEndRoleMultisig(
            clientQAR2,
            aidQVI.name,
            aidQAR2,
            [aidQAR1, aidQAR3],
            aidQVI,
            timestamp
        );
        const opList3 = await addEndRoleMultisig(
            clientQAR3,
            aidQVI.name,
            aidQAR3,
            [aidQAR1, aidQAR2],
            aidQVI,
            timestamp
        );

        await Promise.all(opList1.map((op) => waitOperation(clientQAR1, op)));
        await Promise.all(opList2.map((op) => waitOperation(clientQAR2, op)));
        await Promise.all(opList3.map((op) => waitOperation(clientQAR3, op)));

        await waitAndMarkNotification(clientQAR1, '/multisig/rpy');
        await waitAndMarkNotification(clientQAR2, '/multisig/rpy');

        [oobiQVIbyQAR1, oobiQVIbyQAR2, oobiQVIbyQAR3] = await Promise.all([
            clientQAR1.oobis().get(aidQVI.name, 'agent'),
            clientQAR2.oobis().get(aidQVI.name, 'agent'),
            clientQAR3.oobis().get(aidQVI.name, 'agent'),
        ]);
    }
    assert.equal(oobiQVIbyQAR1.role, oobiQVIbyQAR2.role);
    assert.equal(oobiQVIbyQAR1.role, oobiQVIbyQAR3.role);
    assert.equal(oobiQVIbyQAR1.oobis[0], oobiQVIbyQAR2.oobis[0]);
    assert.equal(oobiQVIbyQAR1.oobis[0], oobiQVIbyQAR3.oobis[0]);




    // Step - QVI Rotation
    if (true) {
        let nameQAR1 = aidQAR1.name;
        let nameQAR2 = aidQAR2.name;
        let nameQAR3 = aidQAR3.name;
        let nameQVI = aidQVI.name;
        // Members agree out of band to rotate keys
        console.log('Members agree out of band to rotate keys');
        let icpResult1 = await clientQAR1.identifiers().rotate(nameQAR1);
        let op1 = await icpResult1.op();
        op1 = await waitOperation(clientQAR1, op1);
        let aid1 = await clientQAR1.identifiers().get(nameQAR1);

        console.log('QAR1 rotated keys');
        let icpResult2 = await clientQAR2.identifiers().rotate(nameQAR2);
        let op2 = await icpResult2.op();
        op2 = await waitOperation(clientQAR2, op2);
        let aid2 = await clientQAR2.identifiers().get(nameQAR2);
        console.log('QAR2 rotated keys');
        let icpResult3 = await clientQAR3.identifiers().rotate(nameQAR3);
        let op3 = await icpResult3.op();
        op3 = await waitOperation(clientQAR3, op3);
        let aid3 = await clientQAR3.identifiers().get(nameQAR3);
        console.log('QAR3 rotated keys');

        // Update new key states
        op1 = await clientQAR1.keyStates().query(aid2.prefix, '1');
        op1 = await waitOperation(clientQAR1, op1);
        const aid2State = op1['response'];
        op1 = await clientQAR1.keyStates().query(aid3.prefix, '1');
        op1 = await waitOperation(clientQAR1, op1);
        const aid3State = op1['response'];

        op2 = await clientQAR2.keyStates().query(aid3.prefix, '1');
        op2 = await waitOperation(clientQAR2, op2);
        op2 = await clientQAR2.keyStates().query(aid1.prefix, '1');
        op2 = await waitOperation(clientQAR2, op2);
        const aid1State = op2['response'];

        op3 = await clientQAR3.keyStates().query(aid1.prefix, '1');
        op3 = await waitOperation(clientQAR3, op3);
        op3 = await clientQAR3.keyStates().query(aid2.prefix, '1');
        op3 = await waitOperation(clientQAR3, op3);

        let rstates = [aid1State, aid2State, aid3State];
        let states = rstates;

        // Multisig Rotation
        // Member1 initiates a rotation event
        let eventResponse1 = await clientQAR1
            .identifiers()
            .rotate(nameQVI, { states: states, rstates: rstates });
        op1 = await eventResponse1.op();
        let serder = eventResponse1.serder;
        let sigs = eventResponse1.sigs;
        let sigers = sigs.map((sig) => new signify.Siger({ qb64: sig }));

        let ims = signify.d(signify.messagize(serder, sigers));
        let atc = ims.substring(serder.size);
        let rembeds = {
            rot: [serder, atc],
        };

        let smids = states.map((state) => state['i']);
        let recp = [aid2State, aid3State].map((state) => state['i']);

        await clientQAR1
            .exchanges()
            .send(
                nameQAR1,
                nameQVI,
                aid1,
                '/multisig/rot',
                { gid: serder.pre, smids: smids, rmids: smids },
                rembeds,
                recp
            );
        console.log(
            'QAR1 initiates rotation event, waiting for others to join...'
        );

        // Member2 check for notifications and join the rotation event
        let msgSaid = await waitAndMarkNotification(clientQAR2, '/multisig/rot');
        console.log('QAR2 received exchange message to join the rotation event');

        await new Promise((resolve) => setTimeout(resolve, 5000));
        let res = await clientQAR2.groups().getRequest(msgSaid);
        let exn = res[0].exn;

        icpResult2 = await clientQAR2
            .identifiers()
            .rotate(nameQVI, { states: states, rstates: rstates });
        op2 = await icpResult2.op();
        serder = icpResult2.serder;
        sigs = icpResult2.sigs;
        sigers = sigs.map((sig) => new signify.Siger({ qb64: sig }));

        ims = signify.d(signify.messagize(serder, sigers));
        atc = ims.substring(serder.size);
        rembeds = {
            rot: [serder, atc],
        };

        smids = exn.a.smids;
        recp = [aid1State, aid3State].map((state) => state['i']);

        await clientQAR2
            .exchanges()
            .send(
                nameQAR2,
                nameQVI,
                aid2,
                '/multisig/ixn',
                { gid: serder.pre, smids: smids, rmids: smids },
                rembeds,
                recp
            );
        console.log('QAR2 joins rotation event, waiting for others...');

        // Member3 check for notifications and join the rotation event
        msgSaid = await waitAndMarkNotification(clientQAR3, '/multisig/rot');
        console.log('QAR3 received exchange message to join the rotation event');
        res = await clientQAR3.groups().getRequest(msgSaid);
        exn = res[0].exn;

        icpResult3 = await clientQAR3
            .identifiers()
            .rotate(nameQVI, { states: states, rstates: rstates });
        op3 = await icpResult3.op();
        serder = icpResult3.serder;
        sigs = icpResult3.sigs;
        sigers = sigs.map((sig) => new signify.Siger({ qb64: sig }));

        ims = signify.d(signify.messagize(serder, sigers));
        atc = ims.substring(serder.size);
        rembeds = {
            rot: [serder, atc],
        };

        smids = exn.a.smids;
        recp = [aid1State, aid2State].map((state) => state['i']);

        await clientQAR3
            .exchanges()
            .send(
                nameQAR3,
                nameQVI,
                aid3,
                '/multisig/ixn',
                { gid: serder.pre, smids: smids, rmids: smids },
                rembeds,
                recp
            );
        console.log('QAR3 joins rotation event, waiting for others...');


        const queryOp1 = await clientQAR1
            .keyStates()
            .query(aidGEDA.prefix, '1');
        const queryOp2 = await clientQAR2
            .keyStates()
            .query(aidGEDA.prefix, '1');
        const queryOp3 = await clientQAR3
            .keyStates()
            .query(aidGEDA.prefix, '1');

        // Check for completion
        op1 = await waitOperation(clientQAR1, op1);
        op2 = await waitOperation(clientQAR2, op2);
        op3 = await waitOperation(clientQAR3, op3);
        op1 = await waitOperation(clientQAR1, queryOp1);
        op2 = await waitOperation(clientQAR2, queryOp2);
        op3 = await waitOperation(clientQAR3, queryOp3);

        console.log('Multisig rotation completed!');
    }


}, 360000);