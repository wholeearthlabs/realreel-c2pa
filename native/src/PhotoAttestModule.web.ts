// Web stub. RealReel disables capture/upload on web, so callers should never
// reach these on web builds — but throwing here keeps the surface honest.
const unavailable = (fn: string) => async (): Promise<never> => {
  throw new Error(`PhotoAttest.${fn} is not available on web`);
};

export default {
  isHardwareSupported: unavailable('isHardwareSupported'),
  isAppAttestAvailable: unavailable('isAppAttestAvailable'),
  hasKey: unavailable('hasKey'),
  deleteKey: unavailable('deleteKey'),
  generateKey: unavailable('generateKey'),
  getPublicKey: unavailable('getPublicKey'),
  sign: unavailable('sign'),
  getAttestation: unavailable('getAttestation'),
  generateAndAttestKey: unavailable('generateAndAttestKey'),
};
