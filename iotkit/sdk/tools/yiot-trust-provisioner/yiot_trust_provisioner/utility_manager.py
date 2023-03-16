import io
import os
import shutil
import sys
import base64
import json 
from contextlib import contextmanager
from typing import Union, Optional
from datetime import datetime, timezone


from hashlib import sha256
from Cryptodome.Cipher import AES

from yiot_trust_provisioner.core_utils import CRCCCITT
from prettytable import PrettyTable
from virgil_crypto import VirgilCrypto, VirgilKeyPair
from virgil_crypto.hashes import HashAlgorithm
from yiot_trust_provisioner.core_utils import VirgilSignExtractor

from yiot_trust_provisioner import consts
from yiot_trust_provisioner.core_utils.virgil_time import date_to_timestamp, timestamp_to_str
from yiot_trust_provisioner.core_utils.helpers import b64_to_bytes, to_b64

from yiot_trust_provisioner.consts.modes import ProgramModes
from yiot_trust_provisioner.core_utils import helpers
from yiot_trust_provisioner.generators.trustlist import TrustListGenerator
from yiot_trust_provisioner.generators.keys.virgil import VirgilKeyGenerator
from yiot_trust_provisioner.data_types.trustlist_type import Signature, PubKeyStructure
from yiot_trust_provisioner.storage import FileKeyStorage
from yiot_trust_provisioner.storage.db_storage import DBStorage
from yiot_trust_provisioner.storage.tl_version_tinydb_storage import TLVersionTinyDBStorage


class UtilityManager:

    def __init__(
            self,
            util_context
    ):
        self._context = util_context
        self.__ui = self._context.ui
        self.__logger = self._context.logger
        self.__yiot_app_storage_path = os.path.join(self._context.storage_path, "yiot-export")
        self.__license_storage_path = os.path.join(self._context.storage_path, "licenses")
        self.__key_storage_path = os.path.join(self._context.storage_path, "key_storage")
        self.__key_storage_private_keys = os.path.join(self.__key_storage_path, "private")
        self.__key_storage_public_keys = os.path.join(self.__key_storage_path, "pubkeys")

        self.__upper_level_keys_count = 2
        self._utility_list = dict()
        self.__check_db_path()

        # Main db's plugs
        self.__upper_level_pub_keys = self.__init_storage("UpperLevelKeys")
        self.__trust_list_pub_keys = self.__init_storage("TrustListPubKeys")
        self.__factory_priv_keys = self.__init_storage("FactoryPrivateKeys")
        self.__trust_list_version_db = self.__init_storage("TrustListVersions")
        self.__license_pub_keys = self.__init_storage("LicenseKeys")

        # private keys db's
        self.__firmware_priv_keys = self.__init_storage("FirmwarePrivateKeys")
        self.__auth_private_keys = self.__init_storage("AuthPrivateKeys")
        self.__recovery_private_keys = self.__init_storage("RecoveryPrivateKeys")
        self.__trust_list_private_keys = self.__init_storage("TLServicePrivateKeys")
        self.__license_priv_keys = self.__init_storage("LicensePrivateKeys")

        self.__keys_type_to_storage_map = {
            consts.VSKeyTypeS.AUTH:              (self.__auth_private_keys, self.__upper_level_pub_keys),
            consts.VSKeyTypeS.FIRMWARE:          (self.__firmware_priv_keys, self.__upper_level_pub_keys),
            consts.VSKeyTypeS.RECOVERY:          (self.__recovery_private_keys, self.__upper_level_pub_keys),
            consts.VSKeyTypeS.TRUSTLIST:         (self.__trust_list_private_keys, self.__upper_level_pub_keys),
            consts.VSKeyTypeS.FACTORY:           (self.__factory_priv_keys, self.__trust_list_pub_keys),
            consts.VSKeyTypeS.CLOUD:             (None, self.__trust_list_pub_keys),  # private key is stored on cloud
            consts.VSKeyTypeS.LICENSE:           (self.__license_priv_keys, self.__license_pub_keys),
        }
        self.__logger.info("initialization successful")

        # generator plugs
        self.__logger.info("TrustList generator initialization")
        self.__trust_list_generator = TrustListGenerator(self.__ui, self.__trust_list_pub_keys)
        self.__logger.info("initialization successful")

        # chooser
        if self._context.program_mode == ProgramModes.VIRGIL_CRYPTO_ONLY:
            self.key_chooser = self.__db_key_chooser

    def __choose_dates_for_key(self, necessary: bool) -> (int, int):
        """
        Ask user to enter start/expiration dates for keys
        :param necessary: if False - user can skip specifying dates
        :return:          two timestamps, calculated with offset (see date_to_timestamp)
        """
        user_confirmed = False
        start_date = 0
        expiration_date = 0
        if necessary is False:
            user_confirmed = self.__ui.get_user_input(
                "Add start and expiration date for key? [y/n]: ",
                input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
                input_checker_msg="Allowed answers [y/n]. Please try again: ",
                empty_allow=False
            ).upper()

        if necessary or (user_confirmed == "Y"):
            self.__ui.print_message("Please choose start date for key")
            start_date = self.__ui.get_date()
            start_date = date_to_timestamp(*start_date)
            enter_expiration = self.__ui.get_user_input(
                "Enter expiration date? [y/n]: ",
                input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
                input_checker_msg="Allowed answers [y/n]. Please try again: ",
                empty_allow=False
            ).upper()
            if enter_expiration == "Y":
                self.__ui.print_message("Please choose expiration date for key")
                expiration_date = self.__ui.get_date()
                expiration_date = date_to_timestamp(*expiration_date)

        return start_date, expiration_date

    def __choose_expiry_timestamp(self, necessary: bool) -> int:
        """
        Ask user to enter expiration date for a license
        :param necessary: if False - user can skip specifying dates
        :return:          expiration timestamp
        """
        enter_expiration = self.__ui.get_user_input(
            "Enter expiration date? [y/n]: ",
            input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
            input_checker_msg="Allowed answers [y/n]. Please try again: ",
            empty_allow=False
        ).upper()
        if enter_expiration == "Y":
            self.__ui.print_message("Please choose expiration date for a license")
            y, m, d = self.__ui.get_date()
            return int(datetime(y, m, d, tzinfo=timezone.utc).timestamp())
        return 0

    def __init_storage(self, name):

        @contextmanager
        def db_init_logs():
            self.__logger.info("{} initialization".format(name))
            self.__logger.debug("{} db at {}".format(name, storage_path))
            yield
            self.__logger.info("Initialization successful")

        storage_path = os.path.join(self.__key_storage_path, "db", name)
        with db_init_logs():
            if self._context.program_mode == ProgramModes.VIRGIL_CRYPTO_ONLY:
                if name == "TrustListVersions":  # TODO: find better way for storage selection
                    return TLVersionTinyDBStorage(storage_path)
                return DBStorage(storage_path)

    def __db_key_chooser(self, key_type, stage, is_new_key=False, **kwargs):
        if is_new_key:
            return VirgilKeyGenerator(key_type.value)

        greeting_msg = kwargs.get("greeting_msg", "Please choose private key: ")
        suppress_db_warning = kwargs.get("suppress_db_warning", False)

        # filter keys from db by type
        private_keys_db, public_keys_db = self.__keys_type_to_storage_map[key_type]

        private_keys = private_keys_db.get_all_data(suppress_db_warning=suppress_db_warning)
        public_keys = public_keys_db.get_all_data(suppress_db_warning=suppress_db_warning)

        filtered_private_keys = {key_id: info for key_id, info in private_keys.items() if info["type"] == key_type.value}
        filtered_public_keys = {key_id: info for key_id, info in public_keys.items() if info["type"] == key_type.value}

        if not len(filtered_private_keys):
            self.__ui.print_message(
                "Cannot find key with type [{}] inside {}. "
                "Please generate it.".format(key_type.value, os.path.basename(private_keys_db.storage_path))
            )
            self.__logger.info("Private key has not been selected ({})".format(stage))
            return

        # choose key id
        keys_info_list = []
        ids = sorted(filtered_private_keys)
        for key_id in ids:
            info_line = "db: {db}, type: {key_type}, comment: {key_comment}, key_id: {key_id}".format(
                db=os.path.basename(private_keys_db.storage_path),
                key_type=filtered_private_keys[key_id]["type"],
                key_comment=filtered_private_keys[key_id]["comment"],
                key_id=key_id
            )
            keys_info_list.append([info_line])
        self.__ui.print_message(greeting_msg)
        user_choose = self.__ui.choose_from_list(
            keys_info_list,
            "Please enter option number: ",
            "Keys list:"
        )
        key_id = ids[user_choose]

        return VirgilKeyGenerator(
            key_type.value,
            private_key=filtered_private_keys[key_id]["key"],
            public_key=filtered_public_keys[key_id]["key"]
        )

    def __generate_initial_keys(self):
        self.__logger.info("initial generation stage started")
        supress_db_warning = True
        upper_keys = self.__upper_level_pub_keys.get_all_data(suppress_db_warning=supress_db_warning)
        upper_keys_value = upper_keys.values()
        recovery_keys = list(filter(lambda x: x if x["type"] == "recovery" else None, upper_keys_value))

        if len(recovery_keys) >= self.__upper_level_keys_count:
            self.__ui.print_message("Infrastructure already exists. Do you want to DROP and re-create it?")
            user_choice = str(
                self.__ui.get_user_input(
                    "Drop infrastructure? [y/n]: ",
                    input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
                    input_checker_msg="Allowed answers [y/n]. Please try again: ",
                    empty_allow=False
                )
            ).upper()
            if user_choice == "Y":
                self.__logger.info("key storage infrastructure cleaning")
                self.__ui.print_message("Cleaning all data...")
                self.__logger.debug("Removing {}".format(self.__key_storage_path))
                shutil.rmtree(self.__key_storage_path)
                self.__logger.debug("Creating {}".format(self.__key_storage_path))
                os.makedirs(os.path.join(self.__key_storage_path, "db"))
                for path in (self.__key_storage_public_keys, self.__key_storage_private_keys):
                    if os.path.exists(path):
                        shutil.rmtree(path)
                self.__ui.print_message("Data cleaned")
                self.__logger.info("key storage cleaned")
            else:
                return
        for key_number in range(1, int(self.__upper_level_keys_count) + 1):
            self.__logger.info("Recovery Key {} generation (Initial Generation stage)".format(key_number))
            self.__ui.print_message("\nRecovery Key {}:".format(key_number))
            self.__generate_recovery_key()

        for key_number in range(1, int(self.__upper_level_keys_count) + 1):
            self.__logger.info("Auth Key {} generation (Initial Generation stage)".format(key_number))
            self.__ui.print_message("\nAuth Key {}:".format(key_number))
            self.__generate_auth_key()

        for key_number in range(1, int(self.__upper_level_keys_count) + 1):
            self.__logger.info("TrustList Key {} generation (Initial Generation stage)".format(key_number))
            self.__ui.print_message("\nTrustList Key {}:".format(key_number))
            self.__generate_trust_list_key()

        for key_number in range(1, int(self.__upper_level_keys_count) + 1):
            self.__logger.info("Firmware Key {} generation (Initial Generation stage)".format(key_number))
            self.__ui.print_message("\nFirmware Key {}:".format(key_number))
            self.__generate_firmware_key()

        self.__logger.info("Factory Key generation (Initial Generation stage)")
        self.__ui.print_message("\nFactory Key:")
        self.__generate_factory_key()
        self.__logger.info("initial generation stage completed")

    def __export_upper_level_pub_keys(self):
        self.__ui.print_message("Exporting upper level Public Keys...")
        if not os.path.exists(self.__key_storage_public_keys):
            os.mkdir(self.__key_storage_public_keys)
        else:
            helpers.clean_folder_content(self.__key_storage_public_keys)

        storage = self.__upper_level_pub_keys
        for key_id in storage.get_keys():
            key_data = storage.get_value(key_id)
            file_name = key_data["type"] + "_" + key_id + "_" + str(key_data["comment"]) + ".pub"
            file_path = os.path.join(self.__key_storage_public_keys, file_name)
            if key_data["type"] == consts.VSKeyTypeS.RECOVERY.value:
                self.__save_key(key_data=key_data, file_path=file_path)
            else:
                signer_key_data = storage.get_value(key_data["signer_key_id"])
                self.__save_key(key_data=key_data, file_path=file_path, signer_key_data=signer_key_data)
        self.__ui.print_message("Export finished")

    def __generate_trust_list(self, storage=None):
        def increment_version(version):
            # Simply increment tl version
            major, minor, patch, build = current_tl_version.split(".")
            major, minor, patch, build = int(major), int(minor), int(patch), int(build)
            if build < 4294967295:  # build is uint32
                build += 1
            else:
                build = 0
                ver_parts = [patch, minor, major]
                for indx, ver_part in enumerate(ver_parts):
                    if ver_part < 255:
                        ver_parts[indx] += 1
                        break
                else:
                    self.__ui.print_warning("Failed to automatically increment trust list version.")
                    self.__logger.info("Failed to automatically increment trust list version: %s" % current_tl_version)
                    return None
                major, minor, patch = ver_parts[::-1]
            return "{major}.{minor}.{patch}.{build}".format(**locals())

        self.__logger.info("TrustList generation started")
        self.__ui.print_message("\nGenerating TrustList...")

        current_tl_version = self.__trust_list_version_db.get_release_version()
        save_as = "release_version"
        trust_list_storage_path = os.path.join(self.__key_storage_path, "trust_lists", "release")

        # Get version to generate
        self.__ui.print_message("Current TrustList version is {}".format(current_tl_version))
        incremented_version = increment_version(current_tl_version) or ""
        empty_allow = bool(incremented_version)  # allow empty input if version increment was successful
        tl_version = self.__ui.get_user_input(
            "Enter the TrustList version [{}]: ".format(incremented_version),
            input_checker_callback=self.__ui.InputCheckers.tl_version_check,
            input_checker_msg="Trust List version should match following format:"
                              " [0-255].[0-255].[0-255].[0-4294967295]",
            empty_allow=empty_allow
        )
        if not tl_version:
            tl_version = incremented_version
        user_choice = str(
            self.__ui.get_user_input(
                "Are you sure you want change current TrustList version to {} [y/n]: ".format(tl_version),
                input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
                input_checker_msg="Allowed answers [y/n]. Please try again: ",
                empty_allow=False
            )
            ).upper()
        if user_choice == "N":
            self.__ui.print_warning("Operation stopped by user, TrustList version doesn't changed")
            self.__logger.info("TrustList version doesn't changed")
            return
        self.__trust_list_version_db.save(save_as, tl_version)

        # Select signer keys
        auth_key = self.key_chooser(
            consts.VSKeyTypeS.AUTH,
            stage="TrustList generation, Auth Key choosing",
            greeting_msg="Please choose Auth Key for TrustList signing: "
        )
        if not auth_key:
            return
        tl_key = self.key_chooser(
            consts.VSKeyTypeS.TRUSTLIST,
            stage="TrustList generation, TrustList Key choosing",
            greeting_msg="Please choose TrustList Key for TrustList signing: "
        )
        if not tl_key:
            return

        self.__logger.info("TrustList version: {} ".format(tl_version))

        signer_keys = [auth_key, tl_key]

        # Generate Trust list
        tl = self.__trust_list_generator.generate(signer_keys, tl_version)
        self.__ui.print_message("Generation finished")
        self.__ui.print_message("Storing to file...")
        if not storage:
            storage = FileKeyStorage(trust_list_storage_path)
        storage.save(tl, "TrustList")
        self.__ui.print_message("File stored")
        self.__ui.print_message("TrustList generated and stored")
        self.__logger.info("TrustList generation completed")

    def __delete_factory_key(self):
        self.__logger.info("Factory Key deleting")
        self.__ui.print_message("Deleting Factory Key...")
        trust_list_pub_keys = self.__trust_list_pub_keys.get_all_data()
        factory_keys_info = list()
        for tl_list_key in trust_list_pub_keys:
            if trust_list_pub_keys[tl_list_key]["type"] == "factory":
                factory_keys_info.append(
                    ["factory_name: {}".format(trust_list_pub_keys[tl_list_key]["comment"]), tl_list_key]
                )
        if not factory_keys_info:
            self.__logger.info("No Factory Key was found. Nothing to delete")
            self.__ui.print_warning("No Factory Key was found. Nothing to delete")
            return
        user_choice = self.__ui.choose_from_list(
            factory_keys_info,
            "Please choose Factory Key to delete: ",
            "Factory Keys: "
        )
        self.__trust_list_pub_keys.delete_key(factory_keys_info[user_choice][1])
        if factory_keys_info[user_choice][1] in self.__factory_priv_keys.get_keys():
            self.__factory_priv_keys.delete_key(factory_keys_info[user_choice][1])
        self.__ui.print_message("Factory Key deleted")
        key_id = factory_keys_info[user_choice][1]
        self.__logger.info("Factory Key with id: [{}] deleted".format(key_id))

    def __generate_key(
            self,
            key_type: consts.VSKeyTypeS,
            name_for_log: str,
            sign_by_recovery_key: bool,
            add_signature_limit: bool,
            start_date_required: bool,
            extra_card_content: Union[dict, None],
            allowed_count: Optional[int] = None,
            meta_data: Optional[str] = ""
    ):
        self.__logger.info("%s Key generation started" % name_for_log)
        self.__ui.print_message("\nGenerating %s Key..." % name_for_log)

        private_keys_db, public_keys_db = self.__keys_type_to_storage_map[key_type]
        if allowed_count is not None:
            existing_keys = list(filter(lambda x: x["type"] == key_type.value, public_keys_db.get_all_data().values()))
            attempt_number = len(existing_keys) + 1
            if attempt_number > allowed_count:
                self.__logger.error("%s Key generation attempt number %s" % (name_for_log, attempt_number) )
                sys.exit("You try to generate the %s Key #%s,"
                         " while maximum allowed count is %s" % (name_for_log, attempt_number, allowed_count))

        # Prepare generator
        key = self.key_chooser(
            key_type, stage="{} generation".format(name_for_log), is_new_key=True, suppress_db_warning=False
        )
        if not key:
            return

        # Sign by recovery key
        if key_type != consts.VSKeyTypeS.RECOVERY:
            rec_pub_keys = self.__get_recovery_pub_keys()
        else:
            rec_pub_keys = {}

        rec_key_for_sign = None
        if sign_by_recovery_key:
            rec_key_for_sign = self.key_chooser(
                consts.VSKeyTypeS.RECOVERY,
                stage="{} Key generation, Recovery key for signing selection".format(name_for_log),
                greeting_msg="Please choose Recovery Key for signing: ",
                suppress_db_warning=False
            )
            if not rec_key_for_sign:
                return

        # Signature limit
        signature_limit = None
        if add_signature_limit:
            signature_limit = self.__ui.get_user_input(
                "Enter the signature limit number from 1 to 4294967295 [4294967295]: ",
                input_checker_callback=self.__ui.InputCheckers.signature_input_check,
                input_checker_msg="Only the number in range from 1 to 4294967295 is allowed. Please try again: ",
                empty_allow=True
            )

        # Get start/expiration date
        start_date, expiration_date = self.__choose_dates_for_key(necessary=start_date_required)

        # Generate
        if not key.generate(
                rec_pub_keys=rec_pub_keys,
                signature_limit=signature_limit,
                signer_key=rec_key_for_sign,
                start_date=start_date,
                expire_date=expiration_date
        ):
            self.__logger.info("{} Key generation failed".format(name_for_log))
            self.__ui.print_message("{} Key generation failed".format(name_for_log))
            return

        # Enter comment
        comment = self.__ui.get_user_input("Enter comment for %s Key: " % name_for_log)

        # Register card for key
        card_content = dict()
        card_content["start_date"] = start_date
        card_content["expiration_date"] = expiration_date
        card_content["comment"] = comment
        card_content["ec_type"] = key.ec_type_secmodule
        card_content["meta_data"] = meta_data
        card_content["key_type"] = consts.key_type_str_to_num_map[key_type]
        if sign_by_recovery_key:
            card_content["signature"] = key.signature
            card_content["signer_public_key"] = rec_key_for_sign.public_key
            card_content["signer_hash_type"] = rec_key_for_sign.hash_type_secmodule
        if extra_card_content:
            card_content.update(extra_card_content)

        # Save to db
        # - prepare key info to be saved
        key_info = {
            "type": key_type.value,
            "ec_type": key.ec_type_secmodule,
            "start_date": start_date,
            "expiration_date": expiration_date,
            "comment": comment,
            "key": key.public_key,
            "meta_data": meta_data
        }
        if sign_by_recovery_key:
            key_info["signature"] = key.signature
            key_info["signer_key_id"] = rec_key_for_sign.key_id
            key_info["signer_hash_type"] = rec_key_for_sign.hash_type_secmodule

        # - public
        public_keys_db.save(key.key_id, key_info, suppress_db_warning=False)

        # - private
        key_info["key"] = key.private_key
        if self._context.program_mode == ProgramModes.VIRGIL_CRYPTO_ONLY:
            private_keys_db.save(key.key_id, key_info, suppress_db_warning=False)

        # Finish
        self.__ui.print_message("Generation finished")
        self.__logger.info("{key_name} Key id: [{id}] comment: [{comment}] generation completed".format(
            key_name=name_for_log,
            id=key.key_id,
            comment=comment
        ))

    def __generate_auth_key(self):
        self.__generate_key(
            key_type=consts.VSKeyTypeS.AUTH,
            name_for_log="Auth",
            sign_by_recovery_key=True,
            add_signature_limit=False,
            start_date_required=False,
            extra_card_content=None
        )

    def __generate_trust_list_key(self):
        self.__generate_key(
            key_type=consts.VSKeyTypeS.TRUSTLIST,
            name_for_log="TrustList",
            sign_by_recovery_key=True,
            add_signature_limit=False,
            start_date_required=False,
            extra_card_content=None
        )

    def __generate_firmware_key(self):
        self.__generate_key(
            key_type=consts.VSKeyTypeS.FIRMWARE,
            name_for_log="Firmware",
            sign_by_recovery_key=True,
            add_signature_limit=False,
            start_date_required=False,
            extra_card_content=None
        )

    def __generate_factory_key(self):
        extra_card_content = {"factory_info": self._context.factory_info}
        self.__generate_key(
            key_type=consts.VSKeyTypeS.FACTORY,
            name_for_log="Factory",
            sign_by_recovery_key=False,
            add_signature_limit=True,
            start_date_required=True,
            extra_card_content=extra_card_content
        )

    def __generate_recovery_key(self):
        self.__generate_key(
            key_type=consts.VSKeyTypeS.RECOVERY,
            name_for_log="Recovery",
            sign_by_recovery_key=False,
            add_signature_limit=False,
            start_date_required=False,
            extra_card_content=None,
            allowed_count=2
        )

    def __manual_add_public_key(self):
        self.__logger.info("Adding Public Key to db")
        self.__ui.print_message("Manual adding Public Key to db...")
        key_type_list = [
            ["factory", self.__trust_list_pub_keys],
        ]

        type_choice = self.__ui.choose_from_list(key_type_list, "Please choose Key type: ", "Key types:")
        public_key = self.__ui.get_user_input(
            "Enter Public Key (tiny base64): ",
            input_checker_callback=self.__ui.InputCheckers.check_base64,
            input_checker_msg="Can't decode, please ensure it's base64 and try again"
        )
        comment = self.__ui.get_user_input("Enter comment for [{}] Key: ".format(key_type_list[type_choice][0]))
        key_id = CRCCCITT().calculate(b64_to_bytes(public_key))

        key_data = {
            "type": key_type_list[type_choice][0],
            "comment": comment,
            "key": public_key
        }
        key_type_list[type_choice][1].save(str(key_id), key_data)
        self.__logger.info("[{key_type}] Key id: [{key_id}] was added to db".format(
            key_type=key_type_list[type_choice][0],
            key_id=key_id
        ))
        self.__ui.print_message("Key added")

    def __print_all_pub_keys_db(self):
        self.__logger.info("Printing Public Keys from db's started")
        self.__ui.print_message("Printing Public Keys from db's...")
        self.__ui.print_message("\nUpper level Keys: ")
        pt = PrettyTable(["Key Id", "Type", "Comment", "Signed by", "Start", "Expire", "Key"])
        for key in self.__upper_level_pub_keys.get_keys():
            row = self.__upper_level_pub_keys.get_value(key)
            signer_id = row.get("signer_key_id", "")
            pt.add_row([key, row["type"], row["comment"], signer_id, row["start_date"], row["expiration_date"], row["key"]])
        self.__ui.print_message(pt.get_string())
        self.__logger.debug("\nUpper level Keys: \n{}".format(pt.get_string()))
        del pt

        self.__ui.print_message("\nTrustList Keys: ")
        pt = PrettyTable(["Key Id", "Type", "EC type", "Comment", "Start", "Expire", "Key"])
        for key in self.__trust_list_pub_keys.get_keys():
            row = self.__trust_list_pub_keys.get_value(key)
            pt.add_row(
                [key, row["type"], row["ec_type"], row["comment"], row["start_date"], row["expiration_date"], row["key"]]
            )
        self.__ui.print_message(pt.get_string())
        self.__logger.debug("\nTrustList Keys: \n{}".format(pt.get_string()))
        del pt
        self.__logger.info("Printing Public Keys from db's completed")

    def __generate_recovery_by_count(self):
        self.__generate_keys_by_count(consts.VSKeyTypeS.RECOVERY)

    def __generate_auth_by_count(self):
        self.__generate_keys_by_count(consts.VSKeyTypeS.AUTH)

    def __generate_tl_key_by_count(self):
        self.__generate_keys_by_count(consts.VSKeyTypeS.TRUSTLIST)

    def __generate_firmware_by_count(self):
        self.__generate_keys_by_count(consts.VSKeyTypeS.FIRMWARE)

    def __generate_keys_by_count(self, key_type):
        upper_level_keys = self.__upper_level_pub_keys.get_all_data()
        key_type_keys_info = dict()
        for key in upper_level_keys.keys():
            if upper_level_keys[key]["type"] == key_type.value:
                key_type_keys_info[key] = upper_level_keys[key]

        # clean old keys
        for key in key_type_keys_info.keys():
            self.__upper_level_pub_keys.delete_key(key)
            if key_type == consts.VSKeyTypeS.TRUSTLIST:
                if key in self.__trust_list_private_keys.get_keys():
                    self.__trust_list_private_keys.delete_key(key)
            if key_type == consts.VSKeyTypeS.FACTORY:
                if key in self.__factory_priv_keys.get_keys():
                    self.__factory_priv_keys.delete_key(key)
            if self._context.program_mode == ProgramModes.VIRGIL_CRYPTO_ONLY and key_type == consts.VSKeyTypeS.RECOVERY:
                if key in self.__recovery_private_keys.get_keys():
                    self.__recovery_private_keys.delete_key(key)
            if self._context.program_mode == ProgramModes.VIRGIL_CRYPTO_ONLY and key_type == consts.VSKeyTypeS.AUTH:
                if key in self.__auth_private_keys.get_keys():
                    self.__auth_private_keys.delete_key(key)

        if key_type == consts.VSKeyTypeS.RECOVERY:
            for key_number in range(1, int(self.__upper_level_keys_count) + 1):
                self.__ui.print_message("\nGenerate Recovery Key {}:".format(key_number))
                self.__generate_recovery_key()
        if key_type == consts.VSKeyTypeS.AUTH:
            for key_number in range(1, int(self.__upper_level_keys_count) + 1):
                self.__ui.print_message("\nGenerate Auth Key {}:".format(key_number))
                self.__generate_auth_key()
        if key_type == consts.VSKeyTypeS.TRUSTLIST:
            for key_number in range(1, int(self.__upper_level_keys_count) + 1):
                self.__ui.print_message("\nGenerate TrustList Key {}:".format(key_number))
                self.__generate_trust_list_key()
        if key_type == consts.VSKeyTypeS.FIRMWARE:
            for key_number in range(1, int(self.__upper_level_keys_count) + 1):
                self.__ui.print_message("\nGenerate Firmware Key {}:".format(key_number))
                self.__generate_firmware_key()

    def __exit(self):
        sys.exit(0)

    def run_utility(self):
        choice = self.__ui.choose_from_list(self.__utility_list, 'Please enter option number: ')
        cleaned_utility_list = list(filter(lambda x: x != ["---"], self.__utility_list))
        if self._context.skip_confirm:
            user_choice = "Y"
        else:
            user_choice = str(
                self.__ui.get_user_input(
                    "Are you sure you want to choose [{}] [y/n]: ".format(cleaned_utility_list[choice][0]),
                    input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
                    input_checker_msg="Allowed answers [y/n]. Please try again: ",
                    empty_allow=False
                )
            ).upper()

        if user_choice == "N":
            self.run_utility()
        else:
            cleaned_utility_list[choice][1]()

    # ############### Utility Functions ################ #

    def __get_recovery_pub_keys(self, suppress_db_warning=False):
        all_keys = self.__upper_level_pub_keys.get_all_data(suppress_db_warning=suppress_db_warning).values()
        recovery_pub_keys = list(filter(lambda x: x["type"] == consts.VSKeyTypeS.RECOVERY, all_keys))
        return recovery_pub_keys

    @property
    def __utility_list(self):
        if not self._utility_list:
            self._utility_list = []
            self._utility_list.extend([
                ["Initial Generation", self.__generate_initial_keys],
                # ["---"],
                # ["Generate Recovery Key ({})".format(self.__upper_level_keys_count), self.__generate_recovery_by_count],
                # ["---"],
                # ["Generate Auth Key ({})".format(self.__upper_level_keys_count), self.__generate_auth_by_count],
                # ["---"],
                # ["Generate TrustList Key ({})".format(self.__upper_level_keys_count),
                #  self.__generate_tl_key_by_count],
                ["---"],
                ["Generate Factory Key", self.__generate_factory_key],
                ["Delete Factory Key", self.__delete_factory_key],
                # ["---"],
                # ["Generate Firmware Key ({})".format(self.__upper_level_keys_count), self.__generate_firmware_by_count],
                ["---"],
                ["Generate TrustList", self.__generate_trust_list],
                ["---"],
                ["Print all Public Keys from db's", self.__print_all_pub_keys_db],
                # ["Add Public Key to db (Factory)", self.__manual_add_public_key],
                ["---"],
                ["Export data as provision package for Factory", self.__create_provision_pack],
                ["Export upper level Public Keys", self.__export_upper_level_pub_keys],
                ["Export Private Keys", self.__get_all_private_keys],
                ["Export for YIoT app", self.__export_for_yiot],
                ["---"],
                # ["Create Root User", self.__create_root_user],
                # ["Create customer credentials", self.__create_customer_cred],
                ["Generate License", self.__generate_license],
                ["---"],
                ["Exit", self.__exit]
            ])

        return self._utility_list

    def __save_key(self, key_data: dict, file_path: str, signer_key_data: Optional[dict]=None):
        byte_buffer = io.BytesIO()

        # Write public key
        pub_key_type_str = consts.VSKeyTypeS(key_data["type"])
        pub_key = PubKeyStructure(
            start_date=int(key_data["start_date"]),
            expiration_date=int(key_data["expiration_date"]),
            key_type=consts.key_type_str_to_num_map[pub_key_type_str],
            ec_type=int(key_data["ec_type"]),
            meta_data=bytearray(key_data["meta_data"], "utf-8"),
            pub_key=b64_to_bytes(key_data["key"])
        )
        byte_buffer.write(bytes(pub_key))

        # Write signature data
        if signer_key_data:
            signer_key_type_str = consts.VSKeyTypeS(signer_key_data["type"])
            signature = Signature(
                signer_type=int(consts.key_type_str_to_num_map[signer_key_type_str]),
                ec_type=int(signer_key_data["ec_type"]),
                hash_type=int(key_data["signer_hash_type"]),
                sign=b64_to_bytes(key_data["signature"]),
                signer_pub_key=b64_to_bytes(signer_key_data["key"])
            )
            byte_buffer.write(bytes(signature))

        with open(file_path, "wb") as f:
            f.write(byte_buffer.getvalue())

    def __save_private_key(self, key, file_path):
        byte_buffer = io.BytesIO()
        byte_buffer.write(b64_to_bytes(key))
        open(file_path, "wb").write(bytes(byte_buffer.getvalue()))

    def __get_private_keys(self, storage):
        private_dir = self.__key_storage_private_keys
        if not os.path.exists(private_dir):
            os.mkdir(private_dir)

        storage_keys = storage.get_keys()
        if not storage_keys:
            self.__logger.error("Db {} empty or not exist".format(storage.storage_path))
            self.__ui.print_warning("Db {} empty or not exist".format(storage.storage_path))
            return
        for key_id in storage.get_keys():
            key_data = storage.get_value(key_id)
            self.__save_private_key(
                key_data["key"],
                os.path.join(private_dir, key_data["type"] + "_" + key_id + "_" + str(key_data["comment"]) + ".key")
            )

    def __get_all_private_keys(self):
        helpers.clean_folder_content(self.__key_storage_private_keys)
        self.__ui.print_message("Exporting Private Keys...")
        self.__get_private_keys(self.__factory_priv_keys)
        self.__get_private_keys(self.__firmware_priv_keys)
        self.__get_private_keys(self.__auth_private_keys)
        self.__get_private_keys(self.__recovery_private_keys)
        self.__get_private_keys(self.__trust_list_private_keys)
        self.__ui.print_message("Export finished")

    def __long_to_bytes(self, val, endianness='big'):
        byte_buffer = io.BytesIO()
        byte_buffer.write(int(val).to_bytes(4, byteorder=endianness, signed=False))
        return bytearray(byte_buffer.getvalue())

    def __get_storage_key_pairs_data(self, key_type, io_buffer):
        private_keys_db, public_keys_db = self.__keys_type_to_storage_map[key_type]

        storage_keys = private_keys_db.get_keys()
        if not storage_keys:
            self.__logger.error("Db {} empty or not exist".format(private_keys_db.storage_path))
            self.__ui.print_warning("Db {} empty or not exist".format(private_keys_db.storage_path))
            return

        for key_id in private_keys_db.get_keys():
            one_key_pair_buffer = io.BytesIO()
            private_key_info = private_keys_db.get_value(key_id)
            public_key_info =public_keys_db.get_value(key_id)

            # EC type NIST256
            one_key_pair_buffer.write(self.__long_to_bytes(public_key_info["ec_type"]))
            
            # Key type : recovery, auth ...
            key_type_str = consts.VSKeyTypeS(public_key_info["type"])
            one_key_pair_buffer.write(self.__long_to_bytes(consts.key_type_str_to_num_map[key_type_str]))
            
            # Private key
            priv_key = b64_to_bytes(private_key_info["key"])
            one_key_pair_buffer.write(self.__long_to_bytes(len(priv_key)))
            one_key_pair_buffer.write(priv_key)

            # Public key
            pub_key = b64_to_bytes(public_key_info["key"])
            one_key_pair_buffer.write(self.__long_to_bytes(len(pub_key)))
            one_key_pair_buffer.write(pub_key)

            # Start date 
            one_key_pair_buffer.write(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            
            # End date 
            one_key_pair_buffer.write(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

            # Signature
            if "signature" in public_key_info:
                signature_buffer = io.BytesIO()
                signer_id = public_key_info["signer_key_id"]
                signature = public_key_info["signature"]
                signature_hash_type = public_key_info["signer_hash_type"]
                signer_public_key_info = self.__upper_level_pub_keys.get_value(signer_id)

                sign_key_type_str = consts.VSKeyTypeS(signer_public_key_info["type"])
                signature_buffer.write(consts.key_type_str_to_num_map[sign_key_type_str].to_bytes(1, byteorder='big', signed=False))
                signature_buffer.write(signer_public_key_info["ec_type"].to_bytes(1, byteorder='big', signed=False))
                signature_buffer.write(signature_hash_type.to_bytes(1, byteorder='big', signed=False))
                signature_buffer.write(b64_to_bytes(signature))
                signature_buffer.write(b64_to_bytes(signer_public_key_info["key"]))

                signature_data = bytes(signature_buffer.getvalue())
                signature_data_len = len(signature_data)
                one_key_pair_buffer.write(self.__long_to_bytes(signature_data_len))
                one_key_pair_buffer.write(signature_data)
            else:
                one_key_pair_buffer.write(self.__long_to_bytes(0))

            one_keypair_data = bytes(one_key_pair_buffer.getvalue())
            one_keypair_data_len = len(one_keypair_data)
            io_buffer.write(self.__long_to_bytes(one_keypair_data_len))
            io_buffer.write(one_keypair_data)

    def __encrypt_with_password(self, data, password):
        byte_buffer = io.BytesIO()
        byte_buffer.write(data)

        key = sha256(password).digest()
        iv = sha256(key).digest()[:12]
        to_be_enc = bytes(byte_buffer.getvalue())
        to_be_enc_len = len(to_be_enc)
        additional_len = 16 - to_be_enc_len % 16

        byte_buffer.write(bytearray([additional_len] * additional_len))
            
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(bytes(byte_buffer.getvalue()))

        byte_buffer_enc = io.BytesIO()
        byte_buffer_enc.write(ciphertext)
        byte_buffer_enc.write(tag)
        
        return bytes(byte_buffer_enc.getvalue())

    def __request_password(self):
        # Request password to encrypt private key
        while True:
            pass1 = self.__ui.get_password("Enter encryption password: ")
            pass2 = self.__ui.get_password("Confirm encryption password: ")
            if pass1 == pass2:
                break
            else:
                self.__ui.print_message("Passwords are not same, try again please")
        return pass1.encode('utf-8')

    def __export_for_yiot(self):
        password = self.__request_password()
        self.__ui.print_message("Exporting for YIoT application ...")
        shutil.rmtree(self.__yiot_app_storage_path, ignore_errors=True)
        self.__logger.debug("Creating {}".format(self.__yiot_app_storage_path))
        os.makedirs(self.__yiot_app_storage_path)

        byte_buffer = io.BytesIO()

        # Serialize all keys
        self.__get_storage_key_pairs_data(consts.VSKeyTypeS.RECOVERY, byte_buffer)
        self.__get_storage_key_pairs_data(consts.VSKeyTypeS.AUTH, byte_buffer)
        self.__get_storage_key_pairs_data(consts.VSKeyTypeS.TRUSTLIST, byte_buffer)
        self.__get_storage_key_pairs_data(consts.VSKeyTypeS.FIRMWARE, byte_buffer)
        self.__get_storage_key_pairs_data(consts.VSKeyTypeS.FACTORY, byte_buffer)

        # Serialize TrustList
        # - find latest TrustLIst
        trust_lists = helpers.find_files(self.__key_storage_path, "TrustList_")
        if not trust_lists:
            self.__ui.print_error("TrustList needed for YIoT app not found. Please generate it.")
            return
        *_, latest_tl_path = sorted(trust_lists, key=lambda path: os.path.getmtime(path))
        file = open(latest_tl_path, "rb")
        content = file.read()
        file.close()
        byte_buffer.write(self.__long_to_bytes(len(content)))
        byte_buffer.write(content)

        file_path = os.path.join(self.__yiot_app_storage_path, "yiot.rot")
        enc_data = self.__encrypt_with_password(bytes(byte_buffer.getvalue()), password)
        open(file_path, "wb").write(enc_data)

        self.__ui.print_message("Export finished")

    def __create_provision_pack(self):
        # Prepare folder
        if os.path.exists(self._context.provision_pack_path):
            helpers.clean_folder_content(self._context.provision_pack_path)
        else:
            os.makedirs(self._context.provision_pack_path)
        pack_private_keys = os.path.join(self._context.provision_pack_path, "private")
        pack_public_keys = os.path.join(self._context.provision_pack_path, "pubkeys")
        os.makedirs(pack_private_keys)
        os.makedirs(pack_public_keys)

        # Prepare private keys
        self.__get_all_private_keys()

        # Choose factory
        trust_list_pub_keys = self.__trust_list_pub_keys.get_all_data()
        factory_keys_info = list()
        for tl_list_key in trust_list_pub_keys:
            if trust_list_pub_keys[tl_list_key]["type"] == "factory":
                factory_keys_info.append(
                    ["factory_name: {}".format(trust_list_pub_keys[tl_list_key]["comment"]), tl_list_key]
                )

        user_choice = self.__ui.choose_from_list(
            factory_keys_info,
            "Please choose Factory Key to delete: ",
            "Factory Keys: "
        )

        factory_keys = helpers.find_files(self.__key_storage_private_keys, "factory_" + factory_keys_info[user_choice][1])
        if not factory_keys:
            self.__ui.print_error("Factory key needed for provision package not found. Please generate it.")
            return
        *_, factory_key = factory_keys


        # Prepare public keys
        self.__export_upper_level_pub_keys()
        auth_keys = helpers.find_files(self.__key_storage_public_keys, 'auth_')
        recovery_keys = helpers.find_files(self.__key_storage_public_keys, 'recovery_')
        tl_keys = helpers.find_files(self.__key_storage_public_keys, 'tl_')
        firmware_keys = helpers.find_files(self.__key_storage_public_keys, 'firmware_')
        if any(len(keys) != self.__upper_level_keys_count for keys in [auth_keys,
                                                                       recovery_keys,
                                                                       tl_keys,
                                                                       firmware_keys]):
            self.__ui.print_error(
                "Upper level keys amount should be %s. Please generate them." % self.__upper_level_keys_count)
            return

        # TrustList
        # - find latest TrustLIst
        trust_lists = helpers.find_files(self.__key_storage_path, "TrustList_")
        if not trust_lists:
            self.__ui.print_error("TrustList needed for provision package not found. Please generate it.")
            return
        *_, latest_tl_path = sorted(trust_lists, key=lambda path: os.path.getmtime(path))

        # Copy files to pack
        # - private keys
        shutil.copy(factory_key, pack_private_keys)
        # - public keys
        for keys in [auth_keys, recovery_keys, tl_keys, firmware_keys]:
            for key_path in keys:
                shutil.copy(key_path, pack_public_keys)
        # - TrustList
        shutil.copy(latest_tl_path, self._context.provision_pack_path)
        self.__ui.print_message("Provision package for Factory saved as '%s' folder" % self._context.provision_pack_path)

    def __check_db_path(self):
        db_path = os.path.join(self.__key_storage_path, "db")
        if not os.path.exists(db_path):
            os.makedirs(db_path)

    def __create_root_user(self):
        pass

    def __create_customer_cred(self):
        pass

    def __device_lic_file(self, mac):
        return os.path.join("/devices", mac + ".lic")

    def __device_checker(self, user_input):
        lic_file = self.__device_lic_file(user_input)
        return os.path.isfile(lic_file)

    def __lic_file(self, name):
        return os.path.join("/credentials/licenses", name + ".json")

    def __license_checker(self, user_input):
        lic_file = self.__lic_file(user_input)
        return os.path.isfile(lic_file)

    def __generate_license(self):
        self.__logger.info("License generation started")


        # Get device base license
        mac = str(
            self.__ui.get_user_input(
                "Type device MAC address: ",
                input_checker_callback=self.__device_checker,
                input_checker_msg="Device is not registered. Please try again: ",
                empty_allow=False
            )
        )


        # Parse license to get device data
        device_lic_file = self.__device_lic_file(mac)
        f = open(device_lic_file, "r")
        json_str = base64.b64decode(f.read())
        j = json.loads(json_str)
        lic_data = base64.b64decode(j["license"])
        device_data_json = json.loads(lic_data)["device"]


        # Get new license type
        lic_type = str(
            self.__ui.get_user_input(
                "Type license data type: ",
                input_checker_callback=self.__license_checker,
                input_checker_msg="License type is not registered. Please try again: ",
                empty_allow=False
            )
        )
        lic_data_file = self.__lic_file(lic_type)
        f = open(lic_data_file, "r")
        extra_data_json = json.loads(f.read())


        # Get Factory key to sign
        key_for_sign = self.key_chooser(
            consts.VSKeyTypeS.FACTORY,
            stage="License Key generation, Factory key for signing selection",
            greeting_msg="Please choose Recovery Key for signing: ",
            suppress_db_warning=False
            )
        if not key_for_sign:
            return


        # Get expiration timestamp
        expiration_timestamp = self.__choose_expiry_timestamp(necessary=False)


        # Prepare to be signed data
        license_content = dict()
        license_content["timestamp"] = int(datetime.now().timestamp())
        license_content["device"] = device_data_json
        license_content["data"] = extra_data_json
        if expiration_timestamp != 0:
            license_content["expire"] = expiration_timestamp
        sign_json = json.dumps(license_content).encode('utf-8')
        to_be_signed = to_b64(sign_json)


        # Sign
        d = to_b64(bytes(to_be_signed, 'utf-8'))
        signature = key_for_sign.sign(d, long_sign=True)

        # Build a final license
        signed_license_content = dict()
        signed_license_content["license"] = to_be_signed
        signed_license_content["signature"] = signature
        signed_lic_json = json.dumps(signed_license_content).encode('utf-8')
        signed_lic_b64 = to_b64(signed_lic_json)


        # Save license
        self.__ui.print_message("Saving License ...")
        license_path = self.__license_storage_path
        os.makedirs(license_path, exist_ok=True)

        now = datetime.now()
        dt_str = mac + "-" + now.strftime("%m_%d_%Y-%H:%M:%S") + ".lic"
        license_file = os.path.join(license_path, dt_str)

        open(license_file, "w").write(signed_lic_b64)


        # Finish
        self.__ui.print_message("Generation finished")
